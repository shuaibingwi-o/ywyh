package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run pcc_client.go <pcc-addr:port>")
		os.Exit(1)
	}
	addr := os.Args[1]

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		fmt.Printf("dial error: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	// Send PCEP Open with sessionID=1
	payload := make([]byte, 8)
	payload[4] = 1 // sessionID
	totalLen := 4 + len(payload)
	msg := make([]byte, totalLen)
	msg[0] = 0x20
	msg[1] = 0x01 // Open
	binary.BigEndian.PutUint16(msg[2:4], uint16(totalLen))
	copy(msg[4:], payload)

	conn.Write(msg)
	fmt.Println("Sent Open")

	// Read response (expect Open response)
	resp := make([]byte, 4096)
	n, err := conn.Read(resp)
	if err != nil {
		fmt.Printf("read error: %v\n", err)
		return
	}
	// PCEP header: version+flags (0), type (1), length (2-3)
	fmt.Printf("Received %d bytes, type=%d\n", n, resp[1])

	// Send Keepalive
	ka := []byte{0x20, 0x02, 0x00, 0x04}
	conn.Write(ka)
	fmt.Println("Sent Keepalive")

	// Control whether to perform PCReq/PCRep exchange. Set to false to
	// preserve the code but not execute it (scripted mode without PCReq/PCRep).
	doPCReq := false

	// Build PCReq with RP (class=2,type=1,len=12, requestID) and END-POINTS IPv4 (class=4,type=1,len=12, src,dst)
	requestID := uint32(100)
	if doPCReq {
		rp := make([]byte, 12)
		rp[0] = 0x02
		rp[1] = 0x01
		binary.BigEndian.PutUint16(rp[2:4], 12)
		binary.BigEndian.PutUint32(rp[4:8], requestID)

		src := net.ParseIP("1.1.1.1").To4()
		dst := net.ParseIP("2.2.2.2").To4()
		ep := make([]byte, 12)
		ep[0] = 0x04
		ep[1] = 0x01
		binary.BigEndian.PutUint16(ep[2:4], 12)
		copy(ep[4:8], src)
		copy(ep[8:12], dst)

		payload = append(rp, ep...)
		totalLen = 4 + len(payload)
		pcReq := make([]byte, totalLen)
		pcReq[0] = 0x20
		pcReq[1] = 0x00
		pcReq[2] = 0x03 // PCReq
		binary.BigEndian.PutUint16(pcReq[3:5], uint16(totalLen))
		copy(pcReq[4:], payload)

		conn.Write(pcReq)
		fmt.Println("Sent PCReq")

		// Read PCRep
		n, err = conn.Read(resp)
		if err != nil {
			fmt.Printf("read error: %v\n", err)
			return
		}
		fmt.Printf("Received PCRep type=%d len=%d\n", resp[2], binary.BigEndian.Uint16(resp[3:5]))
	}

	// Send PCRpt containing SRP object with SRP ID = requestID
	srp := make([]byte, 12)
	srp[0] = 33
	srp[1] = 0x10
	binary.BigEndian.PutUint16(srp[2:4], 12)
	binary.BigEndian.PutUint32(srp[4:8], requestID)
	totalLen = 4 + len(srp)
	pcrpt := make([]byte, totalLen)
	pcrpt[0] = 0x20
	pcrpt[1] = 0x05 // PCRpt
	binary.BigEndian.PutUint16(pcrpt[2:4], uint16(totalLen))
	copy(pcrpt[4:], srp)

	conn.Write(pcrpt)
	fmt.Println("Sent PCRpt")

	// Read PCUpd (type 10)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err = conn.Read(resp)
	if err != nil {
		fmt.Printf("read error waiting for PCUpd: %v\n", err)
		return
	}
	msgType := resp[1]
	fmt.Printf("Received message type=%d len=%d\n", msgType, binary.BigEndian.Uint16(resp[2:4]))

	// crude parse: if ERO present, print SRv6 SID bytes
	length := int(binary.BigEndian.Uint16(resp[3:5]))
	offset := 4
	for offset < length {
		if offset+4 > length {
			break
		}
		objClass := resp[offset]
		objLen := int(binary.BigEndian.Uint16(resp[offset+2 : offset+4]))
		if objLen < 4 || offset+objLen > length {
			break
		}
		if objClass == 7 { // ERO
			// parse subobjects
			sub := offset + 4
			for sub+4 <= offset+objLen {
				if sub+1 >= offset+objLen {
					break
				}
				subType := resp[sub]
				if subType == 0x24 && sub+20 <= offset+objLen {
					ip := net.IP(resp[sub+6 : sub+22])
					fmt.Printf("SRv6 SID: %s\n", ip.String())
					sub += 20
				} else {
					break
				}
			}
		}
		offset += objLen
	}

	fmt.Println("Client done")
}
