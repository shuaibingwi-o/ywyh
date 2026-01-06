package spf

import (
	"context"
	"os"

	"github.com/nttcom/pola/pkg/packet/pcep"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// PCUpd is a small wrapper used by tests/examples to carry a PCEP
// PCUpdMessage plus lightweight metadata (SRP identifier and LSP length).
type PCUpd struct {
	Raw    *pcep.PCUpdMessage
	SRPID  uint32
	LSPLen uint16
}

// Spf holds the pipeline channels and context.
type Spf struct {
	ctx        context.Context
	cancel     context.CancelFunc
	BgpUpdates chan *bgp.BGPMessage
	SrPaths    chan *pcep.PCUpdMessage
}

// NewSpf creates a new Spf instance with provided buffer sizes.
func NewSpf(bufIn, bufOut int) *Spf {
	ctx, cancel := context.WithCancel(context.Background())
	return &Spf{
		ctx:        ctx,
		cancel:     cancel,
		BgpUpdates: make(chan *bgp.BGPMessage, bufIn),
		SrPaths:    make(chan *pcep.PCUpdMessage, bufOut),
	}
}

// Start begins the processing loop. It does not apply updates to the LSDB;
// input layer owns that responsibility.
func (s *Spf) Start() {
	if _, err := os.Stat("config/lsdb.json"); err == nil {
		if GlobalLSDB == nil || (len(GlobalLSDB.Links) == 0 && len(GlobalLSDB.Nodes) == 0) {
			GlobalLSDB = LoadLSDB()
		}
	}
	// Start the internal processing goroutine which listens on
	// `s.BgpUpdates` and produces PCUpd messages to `s.SrPaths`.
	go s.eventLoop()
}

// processLoop listens on the internal `BgpUpdates` channel, applies
// updates to the LSDB, computes paths, packages PCUpd messages and
// forwards them to `SrPaths` until the context is cancelled or the
// channel is closed.
func (s *Spf) eventLoop() {
	defer close(s.SrPaths)
	for {
		select {
		case <-s.ctx.Done():
			return
		case m, ok := <-s.BgpUpdates:
			if !ok {
				return
			}
			// First, apply the BGP update to the LSDB. If the update
			// did not modify the LSDB, skip PCUpd construction and
			// avoid sending a message to consumers.
			changed := ApplyBGPUpdateToLSDB(m)
			var pc *PCUpd
			if !changed {
				// If the message is synthetic (has a registered SRP ID),
				// emit a PCUpd reporting the current LSP length so tests
				// and consumers can observe topology size. Otherwise
				// skip emitting.
				if GetSRPID(m) != 0 {
					db := GetGlobalLSDB()
					lspLen := len(db.Links)
					if lspLen > 16 {
						lspLen = 16
					}
					pc = NewPCUpd(GetSRPID(m), uint16(lspLen))
				} else {
					continue
				}
			} else {
				pc = PackPCUpd(m)
			}
			select {
			case s.SrPaths <- pc.Raw:
			case <-s.ctx.Done():
				return
			}
		}
	}
}

// StartListener removed — external callers should send *bgp.BGPMessage
// values directly into `s.BgpUpdates`. The internal `processLoop`
// handles LSDB updates and PCUpd packaging.

// Stop cancels processing and persists the LSDB.
func (s *Spf) Stop() {
	s.cancel()
	SaveLSDB(GetGlobalLSDB())
}
