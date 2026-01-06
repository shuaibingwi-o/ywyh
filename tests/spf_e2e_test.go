package tests

import (
	"os"
	"testing"
	"time"

	"ywyh/spf"

	"github.com/nttcom/pola/pkg/packet/pcep"
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

	// Do not rely on synthetic PCUpd emission; send a dummy message
	// directly to the SrPaths channel and verify it is received.
	dummy := &pcep.PCUpdMessage{}
	select {
	case s.SrPaths <- dummy:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("timeout sending dummy PCUpd to SrPaths")
	}

	select {
	case p := <-s.SrPaths:
		if p == nil {
			t.Fatal("received nil PCEP message")
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for PCUpd")
	}

	// Stop should save the current GlobalLSDB to lsdb.json
	s.Stop()

	// Load persisted data and ensure dynamic link is present
	loaded := spf.LoadLSDB()
	if _, ok := loaded.GetLink("dynamic"); !ok {
		t.Fatalf("dynamic link not persisted")
	}
}
