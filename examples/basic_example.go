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
	"fmt"
	"time"

	"ywyh/spf"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
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
}
