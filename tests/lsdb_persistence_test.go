package main

import (
	"os"
	"path/filepath"
	"testing"

	"ywyh/spf"
)

func TestLSDBSaveLoad(t *testing.T) {
	tmp := t.TempDir()

	// switch to temp dir so SaveLSDB writes lsdb.json there
	oldwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd failed: %v", err)
	}
	defer os.Chdir(oldwd)
	if err := os.Chdir(tmp); err != nil {
		t.Fatalf("Chdir failed: %v", err)
	}

	// construct LSDB and add entries
	db := spf.NewLSDB()
	db.AddNode(&spf.Node{RouterId: 1, Msd: 0, AsNum: 65000, Locator: "loc1"})
	db.AddLink(&spf.Link{InfId: "lnkA", Loss: 0.1, Delay: 1.0, Status: true, Sid: "sidA"})

	// save to lsdb.json
	spf.SaveLSDB(db)

	// ensure file exists
	fpath := filepath.Join(tmp, "lsdb.json")
	if _, err := os.Stat(fpath); err != nil {
		t.Fatalf("lsdb.json not found: %v", err)
	}

	// load and verify contents
	got := spf.LoadLSDB()
	if got == nil {
		t.Fatalf("LoadLSDB returned nil")
	}
	if _, ok := got.GetLink("lnkA"); !ok {
		t.Fatalf("loaded LSDB missing link lnkA")
	}
	if node, ok := got.GetNode(1); !ok || node.RouterId != 1 {
		t.Fatalf("loaded LSDB missing node 1 or mismatch: %#v %v", node, ok)
	}
}
