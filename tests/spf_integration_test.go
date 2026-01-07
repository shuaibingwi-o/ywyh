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
	spf.GlobalLSDB.AddLink(&spf.Link{InfId: "lnk1"})
	spf.GlobalLSDB.AddLink(&spf.Link{InfId: "lnk2"})

	s := spf.NewSpf(1, 1)
	s.Start()
	defer s.Stop()

	// Directly call PackPCUpd with a BGP message (SRP ID currently unused).
	m := &bgp.BGPMessage{}
	pc := spf.PackPCUpd(m)
	if pc == nil {
		t.Fatal("PackPCUpd returned nil")
	}
}
