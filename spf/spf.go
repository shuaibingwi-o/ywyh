// Package spf implements a small SRv6 path conversion pipeline.
// It consumes BGP update messages, consults the LSDB, and emits
// SRv6 path representations.
package spf

import (
	"context"
	"os"
)

// Spf receives BGPUpdateMessage on `BgpUpdates` and emits SRv6Paths on `SrPaths`.
// Spf runs a small conversion pipeline: receive updates, convert, emit.
type Spf struct {
	ctx        context.Context
	cancel     context.CancelFunc
	BgpUpdates chan BGPUpdateMessage
	SrPaths    chan SRv6Paths
}

// NewSpf creates a new Spf with the provided buffer sizes for channels.
func NewSpf(bufIn, bufOut int) *Spf {
	ctx, cancel := context.WithCancel(context.Background())
	return &Spf{
		ctx:        ctx,
		cancel:     cancel,
		BgpUpdates: make(chan BGPUpdateMessage, bufIn),
		SrPaths:    make(chan SRv6Paths, bufOut),
	}
}

// Start runs the processing loop in a goroutine and begins handling updates.
func (s *Spf) Start() {
	// If a persisted LSDB is present in the current working directory
	// under the `config` directory, load it so the pipeline starts with persisted state.
	if _, err := os.Stat("config/lsdb.json"); err == nil {
		// Only load persisted LSDB if the current GlobalLSDB appears empty,
		// so tests that set up an in-memory LSDB aren't overridden.
		if GlobalLSDB == nil || (len(GlobalLSDB.Links) == 0 && len(GlobalLSDB.Nodes) == 0) {
			GlobalLSDB = LoadLSDB()
		}
	}

	go func() {
		for {
			select {
			case <-s.ctx.Done():
				close(s.SrPaths)
				return
			case m, ok := <-s.BgpUpdates:
				if !ok {
					close(s.SrPaths)
					return
				}
				// Convert and send SRv6Paths (best-effort, non-blocking when possible)
				sp := convertBGPToSRv6Paths(&m)
				select {
				case s.SrPaths <- sp:
				case <-s.ctx.Done():
					close(s.SrPaths)
					return
				default:
				}
			}
		}
	}()
}

// Stop stops the Spf processing loop and cancels its context.
func (s *Spf) Stop() {
	// Stop processing first, then persist the LSDB to disk.
	s.cancel()
	SaveLSDB(GetGlobalLSDB())
}

// convertBGPToSRv6Paths converts a BGPUpdateMessage into a minimal
// SRv6Paths structure, using the GlobalLSDB to populate ERO submodules.
func convertBGPToSRv6Paths(m *BGPUpdateMessage) SRv6Paths {
	var sp SRv6Paths
	// Set srpID from message length as a simple identifier.
	sp.srpObj.srpID = uint32(m.len)

	// Use the global LSDB to populate LSP/ERO info.
	db := GetGlobalLSDB()
	db.mu.RLock()
	// number of links -> determine reported lsp length (capped for large DBs)
	linkCount := len(db.Links)

	// Build a small ero submodule per link (limited to avoid huge messages)
	max := 16
	if linkCount < max {
		max = linkCount
	}
	subs := make([]srEROSubobject, 0, max)
	i := 0
	for id, lk := range db.Links {
		if i >= max {
			break
		}
		sid := []byte(id)
		sl := srEROSubobject{
			selfType: 1,
			length:   uint8(len(sid)),
			flags:    0,
			sid:      sid,
		}
		// attach a lightweight adjacency entry if link contains an InfId
		if lk != nil {
			// append a link-local adj with empty address and inf set to 0
			sl.adj = []linkLocalAdj{{inf: 0}}
		}
		subs = append(subs, sl)
		i++
	}
	// report the LSP length as the number of submodules attached (capped)
	sp.lspObj.header.length = uint16(len(subs))
	sp.eroObj.submodules = subs
	db.mu.RUnlock()

	return sp
}
