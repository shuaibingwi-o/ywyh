package main

import (
	"testing"
	"time"

	"ywyh/spf"
)

func TestSpfPipelineMovedToTests(t *testing.T) {
	spf.GlobalLSDB = spf.NewLSDB()
	spf.GlobalLSDB.AddLink(&spf.Link{InfId: "lnk1"})
	spf.GlobalLSDB.AddLink(&spf.Link{InfId: "lnk2"})

	s := spf.NewSpf(1, 1)
	s.Start()
	defer s.Stop()

	msg := spf.NewBGPUpdate(123)
	s.BgpUpdates <- msg

	select {
	case sp, ok := <-s.SrPaths:
		if !ok {
			t.Fatal("SrPaths channel closed unexpectedly")
		}
		if sp.SRPID() != uint32(123) {
			t.Fatalf("unexpected srpID: got %d want %d", sp.SRPID(), 123)
		}
		if sp.LSPLength() != uint16(len(spf.GlobalLSDB.Links)) {
			t.Fatalf("unexpected lsp length: got %d want %d", sp.LSPLength(), len(spf.GlobalLSDB.Links))
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for SRv6Paths")
	}
}
