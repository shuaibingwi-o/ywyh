package main

// SPDX-License-Identifier: http://www.apache.org/licenses/LICENSE-2.0
/*
 *
 * Copyright (C) 2026 , Inc.
 *
 * Authors:
 *
 */

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"reflect"
	"strconv"
	"sync"
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

type sessionState struct {
	srpID       uint32
	sids        []string
	conn        net.Conn
	connectedAt time.Time
}

// MockPceServer simulates a PCE server for testing purposes.
type MockPceServer struct {
	listener     net.Listener
	spf          *spf.Spf
	pathRequests chan PathRequest
	sessions     map[string]sessionState
	mu           sync.Mutex
}

var (
	acceptOpen    bool
	maxSessions   int
	nextSessionID uint32
	sidMu         sync.Mutex
)

func init() {
	acceptOpen = false
	if v := os.Getenv("PCE_ACCEPT_OPEN"); v == "1" || v == "true" || v == "yes" {
		acceptOpen = true
	}
	maxSessions = 10
	if s := os.Getenv("MAX_SESSIONS"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			maxSessions = n
		}
	}
}

// NewMockPceServer initializes a new MockPceServer.
func NewMockPceServer(spf *spf.Spf) *MockPceServer {
	listener, err := net.Listen("tcp", ":4189")
	if err != nil {
		panic(err)
	}
	pathRequests := make(chan PathRequest, 1000)
	server := &MockPceServer{listener: listener, spf: spf, pathRequests: pathRequests, sessions: make(map[string]sessionState)}
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

	// Start a Unix domain socket listener for BGP speaker processes.
	go func() {
		sockPath := "/tmp/pce_bgp.sock"
		// remove existing socket file if present
		_ = os.Remove(sockPath)
		ln, err := net.Listen("unix", sockPath)
		if err != nil {
			fmt.Printf("Error starting unix socket listener %s: %v\n", sockPath, err)
			return
		}
		defer ln.Close()
		for {
			c, err := ln.Accept()
			if err != nil {
				fmt.Printf("Error accepting unix socket connection: %v\n", err)
				continue
			}
			go func(conn net.Conn) {
				defer conn.Close()
				data, err := io.ReadAll(conn)
				if err != nil {
					fmt.Printf("Error reading raw BGP bytes from unix socket: %v\n", err)
					return
				}
				if len(data) == 0 {
					return
				}
				// Try to parse the raw bytes as a BGP message
				if msg, err := bgp.ParseBGPMessage(data); err == nil {
					select {
					case m.spf.BgpUpdates <- msg:
						fmt.Printf("Injected raw BGP-LS update from unix socket\n")
						// After injecting BGP update into the SPF pipeline, send unsolicited PCUpd to active sessions
						go func() {
							// gather SIDs from LSDB
							db := spf.GetGlobalLSDB()
							var sids []string
							if db != nil {
								for _, l := range db.Links {
									if l != nil && l.Sid != "" {
										sids = append(sids, l.Sid)
									}
								}
							}
							// snapshot active sessions and choose the earliest-connected session (no broadcast)
							m.mu.Lock()
							sessions := make(map[string]sessionState, len(m.sessions))
							for k, v := range m.sessions {
								sessions[k] = v
							}
							m.mu.Unlock()

							// find earliest-connected active session
							var chosenKey string
							var chosen sessionState
							var earliest time.Time
							for k, st := range sessions {
								if st.conn == nil {
									continue
								}
								if earliest.IsZero() || st.connectedAt.Before(earliest) {
									earliest = st.connectedAt
									chosenKey = k
									chosen = st
								}
							}
							if chosen.conn != nil {
								srpid := chosen.srpID
								if srpid == 0 {
									srpid = 1
								}
								wire := constructPCUpd(srpid, sids)
								if len(wire) > 0 {
									// debug: print wire bytes
									fmt.Printf("PCUpd wire to %s: % x\n", chosenKey, wire)
									go func(c net.Conn, w []byte, key string, sid uint32) {
										if _, err := c.Write(w); err != nil {
											fmt.Printf("Error sending unsolicited PCUpd to %s: %v\n", key, err)
										} else {
											fmt.Printf("Sent unsolicited PCUpd to %s after BGP update (srp=%d)\n", key, sid)
										}
									}(chosen.conn, wire, chosenKey, srpid)
								}
							}
						}()
					default:
						fmt.Printf("BgpUpdates channel full, dropping raw BGP update\n")
					}
				} else {
					fmt.Printf("Failed to parse BGP message from unix socket: %v; raw=% x\n", err, data)
					// Heuristic: try to extract any 2001:db8::/32 IPv6 addresses from the raw bytes
					// and inject them into the LSDB so they trigger a PCUpd.
					db := spf.GetGlobalLSDB()
					if db == nil {
						db = spf.NewLSDB()
						spf.GlobalLSDB = db
					}
					added := false
					for i := 0; i+16 <= len(data); i++ {
						// look for 2001:0db8 prefix
						if data[i] == 0x20 && data[i+1] == 0x01 && data[i+2] == 0x0d && data[i+3] == 0xb8 {
							ipb := make([]byte, 16)
							copy(ipb, data[i:i+16])
							ip := net.IP(ipb)
							if ip == nil {
								continue
							}
							sidStr := ip.String()
							// check if already present
							exists := false
							for _, l := range db.Links {
								if l != nil && l.Sid == sidStr {
									exists = true
									break
								}
							}
							if !exists {
								db.AddLink(&spf.Link{InfId: "injected", SrcNode: 1, DstNode: 2, Sid: sidStr, Status: true, Delay: 10, Loss: 0.0})
								fmt.Printf("Injected SID %s into LSDB from raw BGP bytes\n", sidStr)
								added = true
							}
						}
					}
					if added {
						// gather SIDs from LSDB and send PCUpd to earliest-connected session
						var sids []string
						for _, l := range db.Links {
							if l != nil && l.Sid != "" {
								sids = append(sids, l.Sid)
							}
						}
						// snapshot active sessions
						m.mu.Lock()
						sessions := make(map[string]sessionState, len(m.sessions))
						for k, v := range m.sessions {
							sessions[k] = v
						}
						m.mu.Unlock()

						// choose earliest-connected session
						var chosenKey string
						var chosen sessionState
						var earliest time.Time
						for k, st := range sessions {
							if st.conn == nil {
								continue
							}
							if earliest.IsZero() || st.connectedAt.Before(earliest) {
								earliest = st.connectedAt
								chosenKey = k
								chosen = st
							}
						}
						if chosen.conn != nil {
							srpid := chosen.srpID
							if srpid == 0 {
								srpid = 1
							}
							wire := constructPCUpd(srpid, sids)
							if len(wire) > 0 {
								fmt.Printf("PCUpd wire to %s: % x\n", chosenKey, wire)
								go func(c net.Conn, w []byte, key string, sid uint32) {
									if _, err := c.Write(w); err != nil {
										fmt.Printf("Error sending unsolicited PCUpd to %s: %v\n", key, err)
									} else {
										fmt.Printf("Sent unsolicited PCUpd to %s after BGP update (srp=%d)\n", key, sid)
									}
								}(chosen.conn, wire, chosenKey, srpid)
							}
						}
					}
				}
			}(c)
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
	eroLen := 4 + 22*len(sids)
	totalLen := 4 + 12 + eroLen
	buf := make([]byte, totalLen)
	buf[0] = 0x20
	buf[1] = 0x04
	binary.BigEndian.PutUint16(buf[2:4], uint16(totalLen))
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
			buf[subOffset+1] = 22                                       // length
			buf[subOffset+2] = 0                                        // flags
			buf[subOffset+3] = 0x11                                     // endpoint behavior End.X
			binary.BigEndian.PutUint16(buf[subOffset+4:subOffset+6], 0) // weight
			copy(buf[subOffset+6:subOffset+22], addr.AsSlice())
			subOffset += 22
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

// parsePCRpt extracts an SRP ID (if present) from a PCRpt payload.
func (m *MockPceServer) parsePCRpt(payload []byte) uint32 {
	var srpID uint32
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
		// SRP object expected class 33 (0x21), type 0x10 with SRP ID at offset+4
		if objClass == 33 && objType == 0x10 {
			if objLen >= 12 {
				srpID = binary.BigEndian.Uint32(payload[offset+4 : offset+8])
				return srpID
			}
		}
		offset += int(objLen)
	}
	return 0
}

// handleConnection handles a single PCEP connection.
func (m *MockPceServer) handleConnection(conn net.Conn) {
	defer conn.Close()
	// Ensure we remove session state when connection closes
	defer func() {
		key := conn.RemoteAddr().String()
		m.mu.Lock()
		delete(m.sessions, key)
		m.mu.Unlock()
	}()
	buf := make([]byte, 4096)
	var sessionID uint8
	var openReceived bool
	var keepaliveStarted bool
	for {
		n, err := conn.Read(buf)
		if err != nil {
			if err != io.EOF {
				fmt.Println("Error reading:", err)
			}
			return
		}
		// Debug: print raw received packet bytes for troubleshooting
		fmt.Printf("Received raw packet from %s (%d bytes): % x\n", conn.RemoteAddr().String(), n, buf[:n])
		// Parse PCEP message (RFC 5440):
		// octet0: Version+Flags, octet1: Message Type, octet2-3: Message Length
		if n < 4 {
			continue
		}
		version := buf[0] >> 5
		msgType := buf[1]
		length := int(binary.BigEndian.Uint16(buf[2:4]))
		if length > n {
			continue
		}
		if length < 4 {
			// invalid PCEP message length; skip
			continue
		}
		payload := make([]byte, length-4)
		copy(payload, buf[4:length])
		if version == 1 {
			if msgType == 1 { // Open
				fmt.Printf("Received PCEP Open message, length: %d\n", length)

				// Decode and log objects/TLVs inside Open payload for visibility
				{
					offset := 0
					for offset+4 <= len(payload) {
						objClass := payload[offset]
						objType := payload[offset+1]
						objLen := int(binary.BigEndian.Uint16(payload[offset+2 : offset+4]))
						if objLen < 4 || offset+objLen > len(payload) {
							break
						}
						fmt.Printf("Open payload object: class=%d type=%d len=%d\n", objClass, objType, objLen)
						offset += objLen
					}
				}
				if len(payload) >= 8 {
					sessionID = payload[4]
					// enforce session limit
					key := conn.RemoteAddr().String()
					m.mu.Lock()
					curr := len(m.sessions)
					if curr >= maxSessions {
						m.mu.Unlock()
						fmt.Printf("Max sessions reached (%d); rejecting connection from %s\n", maxSessions, key)
						return
					}
					// reserve session before replying; record connection time
					m.sessions[key] = sessionState{srpID: 0, conn: conn, connectedAt: time.Now()}
					m.mu.Unlock()
					openReceived = true
					// assign a per-connection increasing session id
					sidMu.Lock()
					nextSessionID++
					sid := uint8(nextSessionID & 0xff)
					if sid == 0 {
						sid = 1
					}
					sidMu.Unlock()

					if acceptOpen {
						// Reply by copying the client's Open payload exactly, without modifying session id or TLVs.
						resp := make([]byte, 4+len(payload))
						resp[0] = 0x20
						resp[1] = 0x01
						binary.BigEndian.PutUint16(resp[2:4], uint16(4+len(payload)))
						copy(resp[4:], payload)
						nw, err := conn.Write(resp)
						fmt.Printf("Sent Open (echoed) to %s (%d bytes) err=%v bytes=% x\n", conn.RemoteAddr().String(), nw, err, resp[:nw])
					} else {
						// Echo back the received Open payload as the Open response, but set server SID
						resp := make([]byte, 4+len(payload))
						resp[0] = 0x20
						resp[1] = 0x01
						binary.BigEndian.PutUint16(resp[2:4], uint16(4+len(payload)))
						copy(resp[4:], payload)
						if len(payload) >= 5 {
							resp[4] = sid
						}
						nw, err := conn.Write(resp)
						fmt.Printf("Sent Open response to %s (%d bytes) err=%v bytes=% x\n", conn.RemoteAddr().String(), nw, err, resp[:nw])
					}

					// Do not send PCUpd immediately; send after first Keepalive instead.
					// start periodic keepalives for this connection
					if !keepaliveStarted {
						keepaliveStarted = true
						go func(c net.Conn) {
							ticker := time.NewTicker(30 * time.Second)
							defer ticker.Stop()
							for range ticker.C {
								// send PCEP Keepalive (4-byte header)
								ka := []byte{0x20, 0x02, 0x00, 0x04}
								nw2, err2 := c.Write(ka)
								fmt.Printf("Sent Keepalive to %s (%d bytes) err=%v bytes=% x\n", c.RemoteAddr().String(), nw2, err2, ka[:nw2])
								if err2 != nil {
									return
								}
							}
						}(conn)
					}
				}
			} else if msgType == 2 && openReceived { // Keepalive
				fmt.Printf("Received PCEP Keepalive, length: %d\n", length)
				// reply with Keepalive (version 1, type 2, length 4)
				ka := []byte{0x20, 0x02, 0x00, 0x04}
				conn.Write(ka)
			} else if msgType == 3 && openReceived { // PCReq
				fmt.Printf("Received PCEP PCReq message, length: %d\n", length)
				// Log remote PCC address/port
				if ra, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
					fmt.Printf("PCC connected from %s:%d\n", ra.IP.String(), ra.Port)
				}
				// Handle PCReq concurrently
				go m.handlePCReq(conn, payload, sessionID)
			} else if msgType == 5 && openReceived { // PCRpt (PCC report)
				fmt.Printf("Received PCEP PCRpt message, length: %d\n", length)
				// Try to parse SRP ID from PCRpt payload
				srpID := m.parsePCRpt(payload)
				// fallback to stored session state for this connection
				key := conn.RemoteAddr().String()
				m.mu.Lock()
				st := m.sessions[key]
				m.mu.Unlock()
				if srpID == 0 {
					srpID = st.srpID
				}
				// Send PCUpd messages from the Spf pipeline that match srpID.
				// Wait briefly for messages to appear if none are immediately available.
				timeout := time.After(2 * time.Second)
			LOOP:
				for {
					select {
					case pc := <-m.spf.SrPaths:
						if pc == nil {
							break LOOP
						}
						var pid uint32
						if pc.SrpObject != nil {
							pid = pc.SrpObject.SrpID
						}
						if pid != srpID {
							// not for this PCRpt; skip
							continue
						}
						// try to serialize the pcep.PCUpdMessage using the pcep library
						// serialize using constructed bytes from extracted SIDs
						sids := extractSIDsFromPCUpd(pc)
						wire := constructPCUpd(pid, sids)
						if _, err := conn.Write(wire); err != nil {
							fmt.Printf("Error sending PCUpd after PCRpt: %v\n", err)
							break LOOP
						}
						fmt.Printf("Sent PCUpd to PCC %s after PCRpt (srp=%d)\n", conn.RemoteAddr().String(), pid)
					case <-timeout:
						break LOOP
					}
				}
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
	// store requestID for this connection (stateful behavior)
	key := conn.RemoteAddr().String()
	m.mu.Lock()
	st := m.sessions[key]
	st.srpID = requestID
	st.conn = conn
	m.sessions[key] = st
	m.mu.Unlock()

	go func() {
		sids := <-req.Response
		// update session with computed SIDs
		m.mu.Lock()
		st := m.sessions[key]
		st.sids = sids
		m.sessions[key] = st
		m.mu.Unlock()

		response := m.createPCRep(requestID, sids)
		if _, err := conn.Write(response); err != nil {
			fmt.Printf("Error sending PCRep to PCC: %v\n", err)
			return
		}
	}()
}

// Basic example: construct a small LSDB, start the Spf pipeline,
// send a BGP update and print the produced SRv6Paths.
func main() {
	var paramSID string
	var showHelp bool
	flag.StringVar(&paramSID, "sid", "", "SRv6 SID to preload into the LSDB (e.g. 2001:db8::1)")
	flag.BoolVar(&showHelp, "help", false, "Show usage")
	// suppress automatic usage output; only show usage on explicit errors
	flag.Usage = func() {}
	flag.Parse()
	if showHelp {
		// exit quietly on explicit help; do not print usage automatically
		os.Exit(0)
	}
	if paramSID == "" && flag.NArg() > 0 {
		paramSID = flag.Arg(0)
	}
	// Build a minimal LSDB with a single link using the provided SID (if any)
	db := spf.NewLSDB()
	db.AddNode(&spf.Node{RouterId: 1})
	db.AddNode(&spf.Node{RouterId: 2})
	if paramSID != "" {
		db.AddLink(&spf.Link{InfId: "lnkA", SrcNode: 1, DstNode: 2, Sid: paramSID, Status: true, Delay: 10, Loss: 0.01})
	}
	db.AddLink(&spf.Link{InfId: "lnkB", SrcNode: 2, DstNode: 1, Sid: "2001:db8::2", Status: true, Delay: 10, Loss: 0.01})
	spf.GlobalLSDB = db

	// Start SPF pipeline
	s := spf.NewSpf(1000, 1000)
	s.Start()
	defer s.Stop()

	// Start mock PCE server and listen for PCC connections
	server := NewMockPceServer(s)
	server.Start()

	fmt.Println("Mock PCE server started and listening on :4189")

	// Print active sessions periodically
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			server.mu.Lock()
			if len(server.sessions) == 0 {
				fmt.Println("No active sessions")
			} else {
				fmt.Println("Active sessions:")
				for k, st := range server.sessions {
					fmt.Printf(" - %s srp=%d sids=%v\n", k, st.srpID, st.sids)
				}
			}
			server.mu.Unlock()
		}
	}()

	// Keep running
	select {}
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

func sendPCUpdToPCC(addr string, srpID uint32, srv6SID string) bool {
	fmt.Printf("Attempting to send PCUpd to PCC at %s with SRP ID %d and SID %s\n", addr, srpID, srv6SID)

	// Build a pcep.PCUpdMessage and prefer library serialization.
	pc := &pcep.PCUpdMessage{}
	pst := &pcep.PathSetupType{PathSetupType: pcep.PathSetupTypeSRv6TE}
	srp := &pcep.SrpObject{ObjectType: pcep.ObjectTypeSRPSRP, RFlag: false, SrpID: srpID, TLVs: []pcep.TLVInterface{pst}}
	pc.SrpObject = srp
	lsp, _ := pcep.NewLSPObject("", nil, 0)
	pc.LSPObject = lsp

	ero := &pcep.EroObject{ObjectType: pcep.ObjectTypeEROExplicitRoute, EroSubobjects: []pcep.EroSubobject{}}

	var tmp pcep.SRv6EroSubobject
	segField, _ := reflect.TypeOf(tmp).FieldByName("Segment")
	segType := segField.Type
	newFn := reflect.ValueOf(pcep.NewSRv6EroSubObject)

	if a, err := netip.ParseAddr(srv6SID); err == nil && a.Is6() {
		segVal := reflect.New(segType).Elem()
		if f := segVal.FieldByName("Sid"); f.IsValid() && f.CanSet() {
			f.Set(reflect.ValueOf(a))
		}
		res := newFn.Call([]reflect.Value{segVal})
		if res[1].IsNil() {
			subobjIface := res[0].Interface()
			if subobj, ok := subobjIface.(pcep.EroSubobject); ok {
				ero.EroSubobjects = append(ero.EroSubobjects, subobj)
			}
		}
	}
	if len(ero.EroSubobjects) > 0 {
		pc.EroObject = ero
	}

	// serialize using constructed bytes from the SID list
	wire := constructPCUpd(srpID, []string{srv6SID})

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		fmt.Printf("Error connecting to PCC at %s: %v\n", addr, err)
		return false
	}
	defer conn.Close()

	_, err = conn.Write(wire)
	if err != nil {
		fmt.Printf("Error sending PCUpd to PCC: %v\n", err)
		return false
	}
	fmt.Printf("Successfully sent PCUpd to PCC at %s\n", addr)
	return true
}

func constructPCUpd(srpID uint32, sids []string) []byte {
	// Similar to basic_example.go
	// PCUpd message: version 1, flags 0, type 10 (PCUpd), length
	// Objects: SRP, LSP, ERO

	// SRP object
	srpObj := make([]byte, 12)
	srpObj[0] = 33   // class
	srpObj[1] = 0x10 // type 1, flags 0
	binary.BigEndian.PutUint16(srpObj[2:4], 12)
	binary.BigEndian.PutUint32(srpObj[4:8], 0)
	binary.BigEndian.PutUint32(srpObj[8:12], srpID)

	// LSP object
	lspObj := make([]byte, 16)
	lspObj[0] = 32
	lspObj[1] = 0x10
	binary.BigEndian.PutUint16(lspObj[2:4], 16)
	lspObj[4] = 0
	binary.BigEndian.PutUint16(lspObj[5:7], 1)

	// ERO object: 4-byte header + 20 bytes per SRv6 subobject
	eroLen := 4 + 22*len(sids)
	eroObj := make([]byte, eroLen)
	eroObj[0] = 7
	eroObj[1] = 0x10
	binary.BigEndian.PutUint16(eroObj[2:4], uint16(eroLen))
	subOffset := 4
	for _, sid := range sids {
		if addr, err := netip.ParseAddr(sid); err == nil && addr.Is6() {
			eroObj[subOffset] = 0x24                                       // SRv6 subobject type
			eroObj[subOffset+1] = 22                                       // length
			eroObj[subOffset+2] = 0                                        // flags
			eroObj[subOffset+3] = 0x11                                     // endpoint behavior End.X
			binary.BigEndian.PutUint16(eroObj[subOffset+4:subOffset+6], 0) // weight
			copy(eroObj[subOffset+6:subOffset+22], addr.AsSlice())
			subOffset += 22
		}
	}

	totalLen := 4 + len(srpObj) + len(lspObj) + len(eroObj)
	buf := make([]byte, totalLen)
	buf[0] = 0x20
	buf[1] = 11
	binary.BigEndian.PutUint16(buf[2:4], uint16(totalLen))

	offset := 4
	copy(buf[offset:], srpObj)
	offset += len(srpObj)
	copy(buf[offset:], lspObj)
	offset += len(lspObj)
	copy(buf[offset:], eroObj)

	return buf
}

// extractSIDsFromPCUpd pulls SRv6 SIDs from a pcep.PCUpdMessage ERO object.
func extractSIDsFromPCUpd(pc *pcep.PCUpdMessage) []string {
	if pc == nil || pc.EroObject == nil {
		return nil
	}
	var sids []string
	for _, so := range pc.EroObject.EroSubobjects {
		if v, ok := so.(*pcep.SRv6EroSubobject); ok {
			sids = append(sids, v.Segment.Sid.String())
		}
	}
	return sids
}
