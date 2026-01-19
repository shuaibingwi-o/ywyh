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
	"time"

	"ywyh/spf"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// MockPceServer simulates a PCE server for testing purposes.
type MockPceServer struct {
	listener net.Listener
}

// NewMockPceServer initializes a new MockPceServer.
func NewMockPceServer() *MockPceServer {
	listener, err := net.Listen("tcp", ":4189")
	if err != nil {
		panic(err)
	}
	return &MockPceServer{listener: listener}
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
		payload := buf[4:length]
		if version == 1 && msgType == 3 { // PCReq
			// Parse PCReq
			requestID, src, dst := m.parsePCReq(payload)
			// Compute path
			sids := m.computePath(src, dst)
			// Send PCRep
			response := m.createPCRep(requestID, sids)
			conn.Write(response)
		}
		// Handle other messages if needed
	}
}

// HandleRequest simulates handling a request from a client.
func (m *MockPceServer) HandleRequest(request string) string {
	// Handle PCReq and send PCRep
	if request == "PCReq" {
		return "PCRep: Response to PCReq"
	}
	return "Unknown request"
}

// Basic example: construct a small LSDB, start the Spf pipeline,
// send a BGP update and print the produced SRv6Paths.
func main() {
	db := spf.NewLSDB()
	db.AddNode(&spf.Node{RouterId: 1})
	db.AddNode(&spf.Node{RouterId: 2})
	db.AddLink(&spf.Link{InfId: "lnkA", SrcNode: 1, DstNode: 2, Sid: "2001:db8::1"})
	db.AddLink(&spf.Link{InfId: "lnkB", SrcNode: 2, DstNode: 1, Sid: "2001:db8::2"})
	spf.GlobalLSDB = db

	s := spf.NewSpf(1, 1)
	s.Start()
	defer s.Stop()

	// Start the mock PCE server
	server := NewMockPceServer()
	server.Start()

	// create a synthetic BGP update (SRP ID currently unused)
	msg := &bgp.BGPMessage{}
	// send the parsed BGP message into the pipeline
	s.BgpUpdates <- msg

	select {
	case p := <-s.SrPaths:
		if p == nil {
			fmt.Println("received nil PCEP message")
			return
		}
		fmt.Println("received PCEP message")
	case <-time.After(1 * time.Second):
		fmt.Println("timeout waiting for PCUpd")
	}

	// Simulate server running
	time.Sleep(2 * time.Second)
}
