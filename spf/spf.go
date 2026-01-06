package spf

import (
	"context"
	"os"

	"github.com/nttcom/pola/pkg/packet/pcep"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

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

// eventLoop listens on the internal `BgpUpdates` channel, applies
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
			var pcMsg *pcep.PCUpdMessage
			if !changed {
				// Skip sending any PCUpd when the LSDB was not modified.
				continue
			}
			pcMsg = PackPCUpd(m)
			select {
			case s.SrPaths <- pcMsg:
			case <-s.ctx.Done():
				return
			}
		}
	}
}

// Stop cancels processing and persists the LSDB.
func (s *Spf) Stop() {
	s.cancel()
	SaveLSDB(GetGlobalLSDB())
}
