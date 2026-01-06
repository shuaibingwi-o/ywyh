package tests

import (
	"testing"
	"time"

	"ywyh/spf"

	"github.com/nttcom/pola/pkg/packet/pcep"
)

func TestSpfPipelineMovedToTests(t *testing.T) {
	spf.GlobalLSDB = spf.NewLSDB()
	spf.GlobalLSDB.AddLink(&spf.Link{InfId: "lnk1"})
	spf.GlobalLSDB.AddLink(&spf.Link{InfId: "lnk2"})

	s := spf.NewSpf(1, 1)
	s.Start()
	defer s.Stop()

	// Do not rely on synthetic PCUpd emission; send a dummy message.
	dummy := &pcep.PCUpdMessage{}
	select {
	case s.SrPaths <- dummy:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("timeout sending dummy PCUpd to SrPaths")
	}

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
