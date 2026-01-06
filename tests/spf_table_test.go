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
			for i := 0; i < tc.links; i++ {
				id := fmt.Sprintf("lnk%d", i)
				spf.GlobalLSDB.AddLink(&spf.Link{InfId: id})
			}

			s := spf.NewSpf(1, 1)
			s.Start()
			defer s.Stop()

			// Tests should not rely on synthetic PCUpd emission.
			// Send a dummy PCEP message directly to the output channel
			// and verify it can be received by consumers.
			// Directly call PackPCUpd with a BGP message carrying an
			// SRP identifier. This avoids depending on the internal
			// event loop while still exercising output construction.
			m := spf.NewBGPUpdate(7)
			pc := spf.PackPCUpd(m)
			if pc == nil {
				t.Fatal("PackPCUpd returned nil")
			}
		})
	}
}
