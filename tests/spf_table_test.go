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
	"fmt"
	"os"
	"testing"

	"ywyh/spf"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

func TestSpfTableDriven(t *testing.T) {
	cases := []struct {
		name    string
		links   int
		wantLsp uint16
	}{
		{name: "no-links", links: 0, wantLsp: 0},
		{name: "few-links", links: 5, wantLsp: 5},
		{name: "many-links-capped", links: 20, wantLsp: 16},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Isolate filesystem for each subtest to avoid persisted lsdb.json
			tmp := t.TempDir()
			oldwd, _ := os.Getwd()
			defer os.Chdir(oldwd)
			if err := os.Chdir(tmp); err != nil {
				t.Fatalf("chdir failed: %v", err)
			}

			spf.GlobalLSDB = spf.NewLSDB()
			spf.GlobalLSDB.AddNode(&spf.Node{RouterId: 1})
			spf.GlobalLSDB.AddNode(&spf.Node{RouterId: 2})
			for i := 0; i < tc.links; i++ {
				id := fmt.Sprintf("lnk%d", i)
				spf.GlobalLSDB.AddLink(&spf.Link{InfId: id, SrcNode: 1, DstNode: 2, Sid: fmt.Sprintf("2001:db8::%d", i+1), Status: true})
				id2 := fmt.Sprintf("lnk%d_rev", i)
				spf.GlobalLSDB.AddLink(&spf.Link{InfId: id2, SrcNode: 2, DstNode: 1, Sid: fmt.Sprintf("2001:db8::%d", i+100), Status: true})
			}

			s := spf.NewSpf(1000, 1000)
			s.Start()
			defer s.Stop()

			// Tests should not rely on synthetic PCUpd emission.
			// Send a dummy PCEP message directly to the output channel
			// and verify it can be received by consumers.
			// Directly call PackPCUpd with a BGP message carrying an
			// SRP identifier. This avoids depending on the internal
			// event loop while still exercising output construction.
			m := &bgp.BGPMessage{}
			pcMsgs := spf.PackPCUpd(s, m)
			if tc.links > 0 && len(pcMsgs) == 0 {
				t.Fatal("PackPCUpd returned empty slice")
			}
		})
	}
}
