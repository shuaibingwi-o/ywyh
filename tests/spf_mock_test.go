package main

import (
	"context"
	"testing"
	"time"
)

type mockProc struct {
	stdout []byte
	stderr []byte
	exit   int
	delay  time.Duration
}

func (m *mockProc) Run(ctx context.Context, name string, args ...string) ([]byte, []byte, int, error) {
	if m.delay > 0 {
		select {
		case <-ctx.Done():
			return nil, nil, -1, ctx.Err()
		case <-time.After(m.delay):
		}
	}
	return m.stdout, m.stderr, m.exit, nil
}

func TestMockRunSuccess(t *testing.T) {
	m := &mockProc{stdout: []byte("ok"), exit: 0}
	ctx := context.Background()
	out, _, exit, err := m.Run(ctx, "dummy")
	if err != nil {
		t.Fatalf("mock Run failed: %v", err)
	}
	if exit != 0 {
		t.Fatalf("unexpected exit code: %d", exit)
	}
	if string(out) != "ok" {
		t.Fatalf("unexpected output: %q", string(out))
	}
}

func TestMockRunExitNonZero(t *testing.T) {
	m := &mockProc{stdout: []byte("err"), exit: 2}
	ctx := context.Background()
	_, _, exit, err := m.Run(ctx, "dummy")
	if err != nil {
		t.Fatalf("mock Run returned unexpected error: %v", err)
	}
	if exit == 0 {
		t.Fatalf("expected non-zero exit code")
	}
}
