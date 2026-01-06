package tests

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
		if sp == nil {
			t.Fatal("received nil PCEP message")
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for PCUpd")
	}
}
