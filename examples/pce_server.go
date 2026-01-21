// SPDX-License-Identifier: http://www.apache.org/licenses/LICENSE-2.0
/*
 *
 * Copyright (C) 2026 , Inc.
 *
 * Authors:
 *
 */

package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"time"

	"ywyh/spf"

	"github.com/nttcom/pola/pkg/packet/pcep"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// PathRequest represents a request for path computation.
type PathRequest struct {
	Src      uint32
	Dst      uint32
	Response chan []string
}

// MockPceServer simulates a PCE server for testing purposes.
type MockPceServer struct {
	listener     net.Listener
	spf          *spf.Spf
	pathRequests chan PathRequest
}

// NewMockPceServer initializes a new MockPceServer.
func NewMockPceServer(spf *spf.Spf) *MockPceServer {
	listener, err := net.Listen("tcp", ":4189")
	if err != nil {
		panic(err)
	}
	pathRequests := make(chan PathRequest, 1000)
	server := &MockPceServer{listener: listener, spf: spf, pathRequests: pathRequests}
	server.startWorkers(10) // Start 10 workers
	return server
}

// startWorkers starts a pool of worker goroutines for path computation.
func (m *MockPceServer) startWorkers(numWorkers int) {
	for i := 0; i < numWorkers; i++ {
		go func() {
			for req := range m.pathRequests {
				sids := m.computePath(req.Src, req.Dst)
				req.Response <- sids
			}
		}()
	}
}

// Start starts the server to accept connections.
func (m *MockPceServer) Start() {
	go func() {
		for {
			conn, err := m.listener.Accept()
			if err != nil {
				fmt.Println("Error accepting connection:", err)
				continue
			}
			go m.handleConnection(conn)
		}
	}()
}

// createPCRep creates a PCRep message with the given requestID and path SIDs.
func (m *MockPceServer) createPCRep(requestID uint32, sids []string) []byte {
	if len(sids) == 0 {
		// NO-PATH
		buf := make([]byte, 28)
		buf[0] = 0x20 // version 1, flags 0
		buf[2] = 0x04 // PCRep
		binary.BigEndian.PutUint16(buf[3:5], 28)
		// RP
		buf[4] = 0x02 // class
		buf[5] = 0x10 // type 1, flags 0
		binary.BigEndian.PutUint16(buf[6:8], 12)
		binary.BigEndian.PutUint32(buf[8:12], requestID)
		// NO-PATH
		buf[12] = 0x03 // class
		buf[13] = 0x10 // type 1
		binary.BigEndian.PutUint16(buf[14:16], 8)
		buf[16] = 0x00 // flags
		buf[17] = 0x01 // NI
		return buf
	}
	// With path: RP and ERO
	eroLen := 4 + 20*len(sids)
	totalLen := 4 + 12 + eroLen
	buf := make([]byte, totalLen)
	buf[0] = 0x20
	buf[2] = 0x04
	binary.BigEndian.PutUint16(buf[3:5], uint16(totalLen))
	// RP
	buf[4] = 0x02
	buf[5] = 0x10
	binary.BigEndian.PutUint16(buf[6:8], 12)
	binary.BigEndian.PutUint32(buf[8:12], requestID)
	offset := 12
	// ERO
	buf[offset] = 0x07   // class
	buf[offset+1] = 0x10 // type 1
	binary.BigEndian.PutUint16(buf[offset+2:offset+4], uint16(eroLen))
	subOffset := offset + 4
	for _, sidStr := range sids {
		if addr, err := netip.ParseAddr(sidStr); err == nil && addr.Is6() {
			buf[subOffset] = 0x24                                       // SRv6 subobject type
			buf[subOffset+1] = 20                                       // length
			buf[subOffset+2] = 0                                        // flags
			buf[subOffset+3] = 0x11                                     // endpoint behavior End.X
			binary.BigEndian.PutUint16(buf[subOffset+4:subOffset+6], 0) // weight
			copy(buf[subOffset+6:subOffset+22], addr.AsSlice())
			subOffset += 20
		}
	}
	return buf
}

// computePath computes the path from src to dst and returns the SIDs.
func (m *MockPceServer) computePath(src, dst uint32) []string {
	db := spf.GetGlobalLSDB()
	if db == nil {
		return nil
	}
	path, err := db.CalculatePath(src, dst, spf.MetricComposite)
	if err != nil {
		return nil
	}
	var sids []string
	for _, linkID := range path.Links {
		if link, ok := db.GetLink(linkID); ok {
			if link.Sid != "" {
				sids = append(sids, link.Sid)
			}
		}
	}
	return sids
}

// parsePCReq parses the PCReq payload to extract requestID, src, dst.
func (m *MockPceServer) parsePCReq(payload []byte) (uint32, uint32, uint32) {
	var requestID, src, dst uint32
	offset := 0
	for offset < len(payload) {
		if offset+4 > len(payload) {
			break
		}
		objClass := payload[offset]
		objType := payload[offset+1]
		objLen := binary.BigEndian.Uint16(payload[offset+2 : offset+4])
		if objLen < 4 || offset+int(objLen) > len(payload) {
			break
		}
		if objClass == 2 && objType == 1 { // RP
			if objLen >= 12 {
				requestID = binary.BigEndian.Uint32(payload[offset+4 : offset+8])
			}
		} else if objClass == 4 && objType == 1 { // END-POINTS IPv4
			if objLen >= 12 {
				src = binary.BigEndian.Uint32(payload[offset+4 : offset+8])
				dst = binary.BigEndian.Uint32(payload[offset+8 : offset+12])
			}
		}
		offset += int(objLen)
	}
	return requestID, src, dst
}

// handleConnection handles a single PCEP connection.
func (m *MockPceServer) handleConnection(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 4096)
	var sessionID uint8
	var openReceived bool
	for {
		n, err := conn.Read(buf)
		if err != nil {
			if err != io.EOF {
				fmt.Println("Error reading:", err)
			}
			return
		}
		// Parse PCEP message
		if n < 4 {
			continue
		}
		version := buf[0] >> 5
		msgType := buf[2]
		length := int(binary.BigEndian.Uint16(buf[3:5]))
		if length > n {
			continue
		}
		payload := make([]byte, length-4)
		copy(payload, buf[4:length])
		if version == 1 {
			if msgType == 1 { // Open
				fmt.Printf("Received PCEP Open message, length: %d\n", length)
				if len(payload) >= 8 {
					sessionID = payload[4]
					openReceived = true
					// Send Open response
					response := []byte{0x20, 0x00, 0x01, 0x00, 0x0c, 0x01, 0x10, 0x00, 0x08, sessionID, 0x00, 0x00}
					conn.Write(response)
				}
			} else if msgType == 3 && openReceived { // PCReq
				fmt.Printf("Received PCEP PCReq message, length: %d\n", length)
				// Handle PCReq concurrently
				go m.handlePCReq(conn, payload, sessionID)
			} else {
				fmt.Printf("Received PCEP message type: %d, length: %d\n", msgType, length)
			}
		} else {
			fmt.Printf("Received non-PCEP message, version: %d, type: %d, length: %d\n", version, msgType, length)
		}
	}
}

// handlePCReq processes a PCReq message concurrently.
func (m *MockPceServer) handlePCReq(conn net.Conn, payload []byte, sessionID uint8) {
	requestID, src, dst := m.parsePCReq(payload)
	fmt.Printf("Parsed PCReq: requestID=%d, src=%d, dst=%d\n", requestID, src, dst)
	m.spf.CurrentSessionInfo = spf.SessionInfo{SessionID: sessionID, RequestID: requestID}
	req := PathRequest{Src: src, Dst: dst, Response: make(chan []string, 1)}
	m.pathRequests <- req // Block until space in queue
	go func() {
		sids := <-req.Response
		response := m.createPCRep(requestID, sids)
		conn.Write(response)
	}()
}

// Basic example: construct a small LSDB, start the Spf pipeline,
// send a BGP update and print the produced SRv6Paths.
func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run pce_server.go <srv6-sid>")
		os.Exit(1)
	}

	paramSID := os.Args[1]

	db := spf.NewLSDB()
	db.AddNode(&spf.Node{RouterId: 1})
	db.AddNode(&spf.Node{RouterId: 2})
	db.AddLink(&spf.Link{InfId: "lnkA", SrcNode: 1, DstNode: 2, Sid: paramSID, Status: true, Delay: 10, Loss: 0.01})
	db.AddLink(&spf.Link{InfId: "lnkB", SrcNode: 2, DstNode: 1, Sid: "2001:db8::2", Status: true, Delay: 10, Loss: 0.01})
	spf.GlobalLSDB = db

	s := spf.NewSpf(1000, 1000)
	s.Start()
	defer s.Stop()

	// Start the mock PCE server
	server := NewMockPceServer(s)
	server.Start()

	// Send a test PCUpd
	go func() {
		time.Sleep(1 * time.Second)
		srpID := uint32(1)
		pc := &pcep.PCUpdMessage{}
		pst := &pcep.PathSetupType{PathSetupType: pcep.PathSetupTypeSRv6TE}
		srp := &pcep.SrpObject{ObjectType: pcep.ObjectTypeSRPSRP, RFlag: false, SrpID: srpID, TLVs: []pcep.TLVInterface{pst}}
		pc.SrpObject = srp
		lsp, _ := pcep.NewLSPObject("", nil, 0)
		pc.LSPObject = lsp
		ero := &pcep.EroObject{ObjectType: pcep.ObjectTypeEROExplicitRoute, EroSubobjects: []pcep.EroSubobject{}}
		pc.EroObject = ero
		fmt.Println("Sending test PCUpd")
		select {
		case s.SrPaths <- pc:
			fmt.Println("PCUpd sent")
		case <-time.After(5 * time.Second):
			fmt.Println("Timeout sending PCUpd")
		}
	}()

	// Construct BGP-LS BGP UPDATE message
	msg := constructBGPLSUpdate(paramSID)
	fmt.Println("Sending BGP-LS UPDATE to SPF")
	// send the parsed BGP message into the pipeline
	s.BgpUpdates <- msg

	// Wait for PCUpd from SPF
	select {
	case pcUpd := <-s.SrPaths:
		if pcUpd == nil {
			fmt.Println("Received nil PCUpd message")
			return
		}
		fmt.Println("Received PCUpd message from SPF (first)")
		// Extract SRP ID and SRv6 SIDs from PCUpd and send to PCC
		srpID := uint32(0)
		if pcUpd.SrpObject != nil {
			srpID = pcUpd.SrpObject.SrpID
			fmt.Printf("PCUpd SRP ID: %d\n", srpID)
		}
		if pcUpd.EroObject != nil && len(pcUpd.EroObject.EroSubobjects) > 0 {
			for _, subobj := range pcUpd.EroObject.EroSubobjects {
				if srv6Sub, ok := subobj.(*pcep.SRv6EroSubobject); ok {
					sid := srv6Sub.Segment.Sid.String()
					if sid != "" {
						fmt.Printf("Sending PCUpd to PCC with SID: %s\n", sid)
						sendPCUpdToPCC("192.168.15.132:4189", srpID, sid)
					}
				}
			}
		} else {
			fmt.Println("PCUpd has no ERO subobjects, skipping send to PCC")
		}
	case <-time.After(10000 * time.Second):
		fmt.Println("Timeout waiting for PCUpd from SPF")
	}

	// Send the same UPDATE again
	fmt.Println("Sending second BGP-LS UPDATE to SPF")
	s.BgpUpdates <- msg

	// Wait for PCUpd from SPF
	select {
	case pcUpd := <-s.SrPaths:
		if pcUpd == nil {
			fmt.Println("Received nil PCUpd message (second)")
		} else {
			fmt.Println("Received PCUpd message from SPF (second) - path changed")
			// Extract SRP ID and send
			if pcUpd.SrpObject != nil {
				// Send if needed
			}
		}
	case <-time.After(5000 * time.Second):
		fmt.Println("No PCUpd for second UPDATE - path did not change")
	}

	// Simulate server running
	time.Sleep(2 * time.Second)
}

func constructBGPLSUpdate(srv6SID string) *bgp.BGPMessage {
	// Construct a proper BGP-LS UPDATE message with Link-State NLRI and SRv6 SID

	// Create LS Link NLRI
	localDesc := &bgp.LsNodeDescriptor{
		Asn:         65000,
		BGPRouterID: netip.MustParseAddr("1.1.1.1"),
	}
	remoteDesc := &bgp.LsNodeDescriptor{
		Asn:         65000,
		BGPRouterID: netip.MustParseAddr("2.2.2.2"),
	}
	localNodeTLV := bgp.NewLsTLVNodeDescriptor(localDesc, bgp.LS_TLV_LOCAL_NODE_DESC)
	remoteNodeTLV := bgp.NewLsTLVNodeDescriptor(remoteDesc, bgp.LS_TLV_REMOTE_NODE_DESC)
	linkNLRI := &bgp.LsLinkNLRI{
		LocalNodeDesc:  &localNodeTLV,
		RemoteNodeDesc: &remoteNodeTLV,
		LinkDesc: []bgp.LsTLVInterface{
			&bgp.LsTLVSrv6EndXSID{
				EndpointBehavior: 0x11,
				Flags:            0,
				Algorithm:        0,
				Weight:           0,
				SIDs:             []netip.Addr{netip.MustParseAddr(srv6SID)},
			},
		},
	}

	lsAddrPrefix := &bgp.LsAddrPrefix{
		Type: bgp.LS_NLRI_TYPE_LINK,
		NLRI: linkNLRI,
	}

	// Create BGP UPDATE message
	update := bgp.NewBGPUpdateMessage([]bgp.PathNLRI{{NLRI: lsAddrPrefix}}, nil, nil)

	return update
}

func sendPCUpdToPCC(addr string, srpID uint32, srv6SID string) {
	fmt.Printf("Attempting to send PCUpd to PCC at %s with SRP ID %d and SID %s\n", addr, srpID, srv6SID)
	// Construct PCUpd message
	msg := constructPCUpd(srpID, srv6SID)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		fmt.Printf("Error connecting to PCC at %s: %v\n", addr, err)
		return
	}
	defer conn.Close()

	_, err = conn.Write(msg)
	if err != nil {
		fmt.Printf("Error sending PCUpd to PCC: %v\n", err)
		return
	}
	fmt.Printf("Successfully sent PCUpd to PCC at %s\n", addr)
}

	fmt.Println("PCUpd sent to PCC successfully")
}

func constructPCUpd(srpID uint32, srv6SID string) []byte {
	// Similar to basic_example.go
	// PCUpd message: version 1, flags 0, type 10 (PCUpd), length
	// Objects: SRP, LSP, ERO

	// SRP object
	srpObj := make([]byte, 12)
	srpObj[0] = 33   // class
	srpObj[1] = 0x10 // type 1, flags 0
	binary.BigEndian.PutUint16(srpObj[2:4], 12)
	binary.BigEndian.PutUint32(srpObj[4:8], srpID)

	// LSP object
	lspObj := make([]byte, 16)
	lspObj[0] = 32
	lspObj[1] = 0x10
	binary.BigEndian.PutUint16(lspObj[2:4], 16)
	lspObj[4] = 0
	binary.BigEndian.PutUint16(lspObj[5:7], 1)

	// ERO object
	eroLen := 4 + 22
	eroObj := make([]byte, eroLen)
	eroObj[0] = 7
	eroObj[1] = 0x10
	binary.BigEndian.PutUint16(eroObj[2:4], uint16(eroLen))
	eroObj[4] = 40
	eroObj[5] = 22
	eroObj[6] = 0
	eroObj[7] = 0
	if addr, err := netip.ParseAddr(srv6SID); err == nil && addr.Is6() {
		copy(eroObj[8:24], addr.AsSlice())
	}
	eroObj[24] = 0x11

	totalLen := 4 + len(srpObj) + len(lspObj) + len(eroObj)
	buf := make([]byte, totalLen)
	buf[0] = 0x20
	buf[2] = 10
	binary.BigEndian.PutUint16(buf[3:5], uint16(totalLen))

	offset := 4
	copy(buf[offset:], srpObj)
	offset += len(srpObj)
	copy(buf[offset:], lspObj)
	offset += len(lspObj)
	copy(buf[offset:], eroObj)

	return buf
}
