package main

import (
	"fmt"
	"testing"
	"time"

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
			spf.GlobalLSDB = spf.NewLSDB()
			for i := 0; i < tc.links; i++ {
				id := fmt.Sprintf("lnk%d", i)
				spf.GlobalLSDB.AddLink(&spf.Link{InfId: id})
			}

			s := spf.NewSpf(1, 1)
			s.Start()
			defer s.Stop()

			s.BgpUpdates <- spf.NewBGPUpdate(7)

			select {
			case p := <-s.SrPaths:
				if p.LSPLength() != tc.wantLsp {
					t.Fatalf("got lsp length %d want %d", p.LSPLength(), tc.wantLsp)
				}
			case <-time.After(500 * time.Millisecond):
				t.Fatal("timeout waiting for SRv6Paths")
			}
		})
	}
}
