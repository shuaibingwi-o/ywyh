package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

func main() {
	socket := "/tmp/pce_bgp.sock"
	if _, err := os.Stat(socket); err != nil {
		fmt.Printf("socket not present: %v\n", err)
		os.Exit(1)
	}
	conn, err := net.Dial("unix", socket)
	if err != nil {
		fmt.Printf("dial unix error: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()
	// Simple placeholder payload
	buf := []byte("BGP-LS-PLACEHOLDER")

	conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, err = conn.Write(buf)
	if err != nil && err != io.EOF {
		fmt.Printf("write error: %v\n", err)
	}
	fmt.Println("sent bgp payload")
}
