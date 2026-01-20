// SPDX-License-Identifier: http://www.apache.org/licenses/LICENSE-2.0
/*
 *
 * Copyright (C) 2026 , Inc.
 *
 * Authors:
 *
 */

package tests

import (
	"testing"

	"ywyh/spf"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

func TestSpfPipelineMovedToTests(t *testing.T) {
	spf.GlobalLSDB = spf.NewLSDB()
	spf.GlobalLSDB.AddNode(&spf.Node{RouterId: 1})
	spf.GlobalLSDB.AddNode(&spf.Node{RouterId: 2})
	spf.GlobalLSDB.AddLink(&spf.Link{InfId: "lnk1", SrcNode: 1, DstNode: 2, Sid: "2001:db8::1", Status: true})
	spf.GlobalLSDB.AddLink(&spf.Link{InfId: "lnk2", SrcNode: 2, DstNode: 1, Sid: "2001:db8::2", Status: true})

	s := spf.NewSpf(1000, 1000)
	s.Start()
	defer s.Stop()

	// Directly call PackPCUpd with a BGP message (SRP ID currently unused).
	m := &bgp.BGPMessage{}
	pcMsgs := spf.PackPCUpd(s, m)
	if len(pcMsgs) == 0 {
		t.Fatal("PackPCUpd returned empty slice")
	}
}
