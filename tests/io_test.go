package main

import (
	"path/filepath"
	"testing"

	"ywyh/spf"
)

type sample struct {
	Name string `json:"name"`
	N    int    `json:"n"`
}

func TestSaveLoadJSON(t *testing.T) {
	tmp := t.TempDir()
	fname := filepath.Join(tmp, "sample.json")

	out := sample{Name: "alice", N: 42}
	if err := spf.SaveJSON(fname, out); err != nil {
		t.Fatalf("SaveJSON failed: %v", err)
	}

	var in sample
	if err := spf.LoadJSON(fname, &in); err != nil {
		t.Fatalf("LoadJSON failed: %v", err)
	}

	if in.Name != out.Name || in.N != out.N {
		t.Fatalf("mismatch after load: got %+v want %+v", in, out)
	}
}
