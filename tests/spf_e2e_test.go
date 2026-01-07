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
	"os"
	"testing"

	"ywyh/spf"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// End-to-end test: when Spf.Start loads LSDB from disk, and Spf.Stop saves
// the (possibly updated) LSDB back to disk.
func TestSpfE2E_LoadAndSaveLSDB(t *testing.T) {
	tmp := t.TempDir()

	// switch to temp dir so lsdb.json is local to this test
	oldwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd failed: %v", err)
	}
	defer os.Chdir(oldwd)
	if err := os.Chdir(tmp); err != nil {
		t.Fatalf("Chdir failed: %v", err)
	}

	// create persisted LSDB with a single link
	persisted := spf.NewLSDB()
	persisted.AddLink(&spf.Link{InfId: "initial"})
	spf.SaveLSDB(persisted)

	// Start Spf: Start should detect lsdb.json and load it into GlobalLSDB
	s := spf.NewSpf(1, 1)
	s.Start()

	// verify loaded link exists
	if _, ok := spf.GlobalLSDB.GetLink("initial"); !ok {
		t.Fatalf("expected initial link to be loaded")
	}

	// mutate the in-memory LSDB and send an update through the pipeline
	spf.GlobalLSDB.AddLink(&spf.Link{InfId: "dynamic"})

	// Directly call PackPCUpd with a BGP message (SRP ID currently unused).
	m := &bgp.BGPMessage{}
	pc := spf.PackPCUpd(m)
	if pc == nil {
		t.Fatal("PackPCUpd returned nil")
	}

	// Stop should save the current GlobalLSDB to lsdb.json
	s.Stop()

	// Load persisted data and ensure dynamic link is present
	loaded := spf.LoadLSDB()
	if _, ok := loaded.GetLink("dynamic"); !ok {
		t.Fatalf("dynamic link not persisted")
	}
}
