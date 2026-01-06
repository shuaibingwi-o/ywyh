package main

import (
	"fmt"
	"time"

	"ywyh/spf"
)

// Basic example: construct a small LSDB, start the Spf pipeline,
// send a BGP update and print the produced SRv6Paths.
func main() {
	db := spf.NewLSDB()
	db.AddLink(&spf.Link{InfId: "lnkA"})
	db.AddLink(&spf.Link{InfId: "lnkB"})
	spf.GlobalLSDB = db

	s := spf.NewSpf(1, 1)
	s.Start()
	defer s.Stop()

	msg := spf.NewBGPUpdate(42)
	// send the parsed BGP message into the pipeline
	s.BgpUpdates <- msg

	select {
	case p := <-s.SrPaths:
		if p == nil {
			fmt.Println("received nil PCUpd")
			return
		}
		fmt.Printf("SRP ID=%d LSP len=%d\n", p.SRPID, p.LSPLen)
	case <-time.After(1 * time.Second):
		fmt.Println("timeout waiting for PCUpd")
	}
}
