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
)

func TestSpfPipelineMovedToTests(t *testing.T) {
	spf.GlobalLSDB = spf.NewLSDB()
	spf.GlobalLSDB.AddLink(&spf.Link{InfId: "lnk1"})
	spf.GlobalLSDB.AddLink(&spf.Link{InfId: "lnk2"})

	s := spf.NewSpf(1, 1)
	s.Start()
	defer s.Stop()

	// Directly call PackPCUpd with a BGP message carrying an SRP ID.
	m := spf.NewBGPUpdate(123)
	pc := spf.PackPCUpd(m)
	if pc == nil {
		t.Fatal("PackPCUpd returned nil")
	}
}
