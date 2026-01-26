package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"

	"ywyh/spf"
)

type sessionState struct {
	srpID       uint32
	sids        []string
	conn        net.Conn
	connectedAt time.Time
}

type PathRequest struct {
	Src      uint32
	Dst      uint32
	Response chan []string
}

type MockPceServer struct {
	spf          *spf.Spf
	sessions     map[string]sessionState
	mu           sync.Mutex
	pathRequests chan PathRequest
}

func NewMockPceServer(s *spf.Spf) *MockPceServer {
	return &MockPceServer{
		spf:          s,
		sessions:     make(map[string]sessionState),
		pathRequests: make(chan PathRequest, 100),
	}
}

func (m *MockPceServer) Start() {
	ln, err := net.Listen("tcp", "[::]:4189")
	if err != nil {
		fmt.Printf("listen fail: %v\n", err)
		os.Exit(1)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				fmt.Printf("accept err: %v\n", err)
				continue
			}
			k := c.RemoteAddr().String()
			m.mu.Lock()
			m.sessions[k] = sessionState{srpID: 0, conn: c, connectedAt: time.Now()}
			m.mu.Unlock()
			go m.handleConnection(c)
		}
	}()
}

func (m *MockPceServer) handleConnection(conn net.Conn) {
	defer conn.Close()
	defer func() {
		k := conn.RemoteAddr().String()
		m.mu.Lock()
		delete(m.sessions, k)
		m.mu.Unlock()
	}()
	buf := make([]byte, 4096)
	var openReceived bool
	for {
		n, err := conn.Read(buf)
		if err != nil {
			if err != io.EOF {
				fmt.Printf("read err: %v\n", err)
			}
			return
		}
		if n < 4 {
			continue
		}
		version := buf[0] >> 5
		msgType := buf[1]
		length := int(binary.BigEndian.Uint16(buf[2:4]))
		if length > n || length < 4 {
			continue
		}
		payload := buf[4:length]
		if version != 1 {
			continue
		}
		switch msgType {
		case 1:
			openReceived = true
			resp := make([]byte, 4+len(payload))
			resp[0] = 0x20
			resp[1] = 0x01
			binary.BigEndian.PutUint16(resp[2:4], uint16(4+len(payload)))
			copy(resp[4:], payload)
			conn.Write(resp)
		case 2:
		case 3:
			if openReceived {
				go m.handlePCReq(conn, payload)
			}
		default:
		}
	}
}

func (m *MockPceServer) handlePCReq(conn net.Conn, payload []byte) {
	reqID, src, dst := m.parsePCReq(payload)
	pr := PathRequest{Src: src, Dst: dst, Response: make(chan []string, 1)}
	select {
	case m.pathRequests <- pr:
	default:
		resp := m.createPCRep(reqID, nil)
		conn.Write(resp)
		return
	}
	k := conn.RemoteAddr().String()
	m.mu.Lock()
	st := m.sessions[k]
	st.srpID = reqID
	st.conn = conn
	m.sessions[k] = st
	m.mu.Unlock()
	sids := <-pr.Response
	resp := m.createPCRep(reqID, sids)
	conn.Write(resp)
}

func (m *MockPceServer) parsePCReq(payload []byte) (uint32, uint32, uint32) {
	var requestID, src, dst uint32
	off := 0
	for off+4 <= len(payload) {
		objClass := payload[off]
		objType := payload[off+1]
		objLen := int(binary.BigEndian.Uint16(payload[off+2 : off+4]))
		if objLen < 4 || off+objLen > len(payload) {
			break
		}
		if objClass == 2 && objType == 1 && objLen >= 12 {
			requestID = binary.BigEndian.Uint32(payload[off+4 : off+8])
		} else if objClass == 4 && objType == 1 && objLen >= 12 {
			src = binary.BigEndian.Uint32(payload[off+4 : off+8])
			dst = binary.BigEndian.Uint32(payload[off+8 : off+12])
		}
		off += objLen
	}
	return requestID, src, dst
}

func (m *MockPceServer) createPCRep(requestID uint32, sids []string) []byte {
	if len(sids) == 0 {
		buf := make([]byte, 28)
		buf[0] = 0x20
		buf[1] = 0x04
		binary.BigEndian.PutUint16(buf[2:4], 28)
		buf[4] = 0x02
		buf[5] = 0x10
		binary.BigEndian.PutUint16(buf[6:8], 12)
		binary.BigEndian.PutUint32(buf[8:12], requestID)
		buf[12] = 0x03
		buf[13] = 0x10
		binary.BigEndian.PutUint16(buf[14:16], 8)
		buf[16] = 0x00
		buf[17] = 0x01
		return buf
	}
	eroLen := 4 + 22*len(sids)
	total := 4 + 12 + eroLen
	buf := make([]byte, total)
	buf[0] = 0x20
	buf[1] = 0x04
	binary.BigEndian.PutUint16(buf[2:4], uint16(total))
	buf[4] = 0x02
	buf[5] = 0x10
	binary.BigEndian.PutUint16(buf[6:8], 12)
	binary.BigEndian.PutUint32(buf[8:12], requestID)
	off := 12
	buf[off] = 0x07
	buf[off+1] = 0x10
	binary.BigEndian.PutUint16(buf[off+2:off+4], uint16(eroLen))
	sub := off + 4
	for _, sid := range sids {
		if a, err := netip.ParseAddr(sid); err == nil && a.Is6() {
			buf[sub] = 0x24
			buf[sub+1] = 22
			buf[sub+2] = 0
			buf[sub+3] = 0x11
			binary.BigEndian.PutUint16(buf[sub+4:sub+6], 0)
			copy(buf[sub+6:sub+22], a.AsSlice())
			sub += 22
		}
	}
	return buf
}

func constructPCUpd(srpID uint32, sids []string) []byte {
	srpObj := make([]byte, 12)
	srpObj[0] = 33
	srpObj[1] = 0x10
	binary.BigEndian.PutUint16(srpObj[2:4], 12)
	binary.BigEndian.PutUint32(srpObj[4:8], 0)
	binary.BigEndian.PutUint32(srpObj[8:12], srpID)

	lspObj := make([]byte, 16)
	lspObj[0] = 32
	lspObj[1] = 0x10
	binary.BigEndian.PutUint16(lspObj[2:4], 16)
	lspObj[4] = 0
	binary.BigEndian.PutUint16(lspObj[5:7], 1)

	eroLen := 4 + 22*len(sids)
	eroObj := make([]byte, eroLen)
	eroObj[0] = 7
	eroObj[1] = 0x10
	binary.BigEndian.PutUint16(eroObj[2:4], uint16(eroLen))
	sub := 4
	for _, sid := range sids {
		if a, err := netip.ParseAddr(sid); err == nil && a.Is6() {
			eroObj[sub] = 0x24
			eroObj[sub+1] = 22
			eroObj[sub+2] = 0
			eroObj[sub+3] = 0x11
			binary.BigEndian.PutUint16(eroObj[sub+4:sub+6], 0)
			copy(eroObj[sub+6:sub+22], a.AsSlice())
			sub += 22
		}
	}

	total := 4 + len(srpObj) + len(lspObj) + len(eroObj)
	buf := make([]byte, total)
	buf[0] = 0x20
	buf[1] = 11
	binary.BigEndian.PutUint16(buf[2:4], uint16(total))
	off := 4
	copy(buf[off:], srpObj)
	off += len(srpObj)
	copy(buf[off:], lspObj)
	off += len(lspObj)
	copy(buf[off:], eroObj)
	return buf
}

func main() {
	var paramSID string
	var lsdbPeriod int
	var logBgp bool
	var logPcUpd bool
	flag.StringVar(&paramSID, "sid", "", "SRv6 SID to preload into the LSDB (e.g. 2001:db8::1)")
	flag.IntVar(&lsdbPeriod, "lsdb-period", 0, "Seconds between LSDB dumps (0 disables)")
	flag.BoolVar(&logBgp, "log-bgp", true, "Log received BGP updates injected via unix socket")
	flag.BoolVar(&logPcUpd, "log-pcupd", true, "Log PCUpd wire bytes and send confirmation")
	flag.Parse()

	db := spf.NewLSDB()
	db.AddNode(&spf.Node{RouterId: 1})
	db.AddNode(&spf.Node{RouterId: 2})
	if paramSID != "" {
		db.AddLink(&spf.Link{InfId: "lnkA", SrcNode: 1, DstNode: 2, Sid: paramSID, Status: true, Delay: 10, Loss: 0.01})
	}
	db.AddLink(&spf.Link{InfId: "lnkB", SrcNode: 2, DstNode: 1, Sid: "2001:db8::2", Status: true, Delay: 10, Loss: 0.01})
	spf.GlobalLSDB = db

	s := spf.NewSpf(1000, 1000)
	// set spf logging flags from CLI
	spf.LogBGPUpdates = logBgp
	spf.LogPCUpdMsgs = logPcUpd
	s.Start()
	defer s.Stop()

	server := NewMockPceServer(s)
	server.Start()

	if lsdbPeriod > 0 {
		go func() {
			ticker := time.NewTicker(time.Duration(lsdbPeriod) * time.Second)
			defer ticker.Stop()
			for range ticker.C {
				fmt.Print(spf.DumpGlobalLSDB())
			}
		}()
	}

	// Unix socket listener for BGP-LS injections into SPF
	go func() {
		sock := "/tmp/pce_bgp.sock"
		// remove previous socket if present
		os.Remove(sock)
		ln, err := net.Listen("unix", sock)
		if err != nil {
			fmt.Printf("failed to listen unix socket %s: %v\n", sock, err)
			return
		}
		defer ln.Close()
		fmt.Printf("Listening for BGP bytes on unix socket %s\n", sock)
		for {
			c, err := ln.Accept()
			if err != nil {
				fmt.Printf("unix accept err: %v\n", err)
				continue
			}
			go func(conn net.Conn) {
				defer conn.Close()
				data, err := io.ReadAll(conn)
				if err != nil {
					fmt.Printf("read unix socket err: %v\n", err)
					return
				}
				msg, err := bgp.ParseBGPMessage(data)
				if err != nil {
					fmt.Printf("bgp parse err: %v\n", err)
					// dump a short hex preview for debugging
					l := len(data)
					if l > 128 {
						l = 128
					}
					fmt.Printf("raw(%d): % x\n", len(data), data[:l])
					return
				}
				select {
				case s.BgpUpdates <- msg:
					if logBgp {
						fmt.Printf("Injected BGP message into SPF\n")
					}
				default:
					if logBgp {
						fmt.Printf("BgpUpdates channel full, dropping message\n")
					}
				}
			}(c)
		}
	}()

	go func() {
		for updates := range s.SrPaths {
			if len(updates) == 0 {
				continue
			}
			server.mu.Lock()
			sessions := make(map[string]sessionState, len(server.sessions))
			for k, v := range server.sessions {
				sessions[k] = v
			}
			server.mu.Unlock()

			var chosenKey string
			var chosen sessionState
			var earliest time.Time
			for k, st := range sessions {
				if st.conn == nil {
					continue
				}
				if ra, ok := st.conn.RemoteAddr().(*net.TCPAddr); ok {
					if ra.IP == nil || ra.IP.To4() != nil {
						continue
					}
				}
				if earliest.IsZero() || st.connectedAt.Before(earliest) {
					earliest = st.connectedAt
					chosenKey = k
					chosen = st
				}
			}
			for _, upd := range updates {
				srpID := uint32(1) // or use a better SRP ID allocation if needed
				if chosen.conn != nil && len(upd.SIDs) > 0 {
					wire := constructPCUpd(srpID, upd.SIDs)
					if len(wire) > 0 {
						if logPcUpd {
							fmt.Printf("[SPF->PCUpd] PCUpd wire to %s: % x\n", chosenKey, wire)
						}
						go func(c net.Conn, w []byte, key string, id uint32) {
							if _, err := c.Write(w); err != nil {
								if logPcUpd {
									fmt.Printf("Error sending PCUpd to %s: %v\n", key, err)
								}
							} else {
								if logPcUpd {
									fmt.Printf("Sent PCUpd to %s from SPF (srp=%d)\n", key, id)
								}
							}
						}(chosen.conn, wire, chosenKey, srpID)
					}
				}
			}
		}
	}()

	fmt.Println("Mock PCE server started on :4189")
	select {}
}
