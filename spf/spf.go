// Package spf implements a small SRv6 path conversion pipeline.
// It consumes BGP update messages, consults the LSDB, and emits
// SRv6 path representations.
package spf

import (
	"context"
	"encoding/binary"
	"os"

	"github.com/nttcom/pola/pkg/packet/pcep"
)

// Spf receives BGPUpdateMessage on `BgpUpdates` and emits SRv6Paths on `SrPaths`.
// Spf runs a small conversion pipeline: receive updates, convert, emit.
type Spf struct {
	ctx        context.Context
	cancel     context.CancelFunc
	BgpUpdates chan BGPUpdateMessage
	// SrPaths now carries the generated PCEP messages only.
	SrPaths chan *pcep.PCEP
}

// NewSpf creates a new Spf with the provided buffer sizes for channels.
func NewSpf(bufIn, bufOut int) *Spf {
	ctx, cancel := context.WithCancel(context.Background())
	return &Spf{
		ctx:        ctx,
		cancel:     cancel,
		BgpUpdates: make(chan BGPUpdateMessage, bufIn),
		SrPaths:    make(chan *pcep.PCEP, bufOut),
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
				// Convert and send the generated PCEP only (best-effort, non-blocking).
				sp := convertBGPToSRv6Paths(&m)
				if sp.RawPCEP != nil {
					select {
					case s.SrPaths <- sp.RawPCEP:
					case <-s.ctx.Done():
						close(s.SrPaths)
						return
					default:
					}
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
	// Update LSDB with any NLRI entries in the BGP update: create nodes.
	// We take a conservative approach: derive a node ID from the NLRI IP
	// (IPv4 -> 4 bytes; IPv6 -> low 4 bytes) and add a lightweight Node.
	if m != nil {
		for _, nl := range m.nlriEntries {
			var nodeID uint32
			if nl.ip.To4() != nil {
				b := nl.ip.To4()
				nodeID = binary.BigEndian.Uint32(b)
			} else if len(nl.ip) >= 16 {
				nodeID = binary.BigEndian.Uint32(nl.ip[len(nl.ip)-4:])
			}
			if nodeID != 0 {
				// ensure node exists
				if _, ok := db.GetNode(nodeID); !ok {
					db.AddNode(&Node{RouterId: nodeID, Locator: nl.ip.String()})
				}
			}
		}
	}

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

	// If the BGP update contains at least two NLRI entries, attempt to
	// compute a shortest path between the first and last NLRI-derived nodes
	// and replace the ERO submodules with the path-specific list.
	if m != nil && len(m.nlriEntries) >= 2 {
		// derive src and dst node IDs the same way as above
		var srcID, dstID uint32
		if m.nlriEntries[0].ip.To4() != nil {
			srcID = binary.BigEndian.Uint32(m.nlriEntries[0].ip.To4())
		} else if len(m.nlriEntries[0].ip) >= 16 {
			srcID = binary.BigEndian.Uint32(m.nlriEntries[0].ip[len(m.nlriEntries[0].ip)-4:])
		}
		last := m.nlriEntries[len(m.nlriEntries)-1]
		if last.ip.To4() != nil {
			dstID = binary.BigEndian.Uint32(last.ip.To4())
		} else if len(last.ip) >= 16 {
			dstID = binary.BigEndian.Uint32(last.ip[len(last.ip)-4:])
		}

		if srcID != 0 && dstID != 0 {
			// compute path using default metric (delay)
			if pathRes, err := db.CalculatePath(srcID, dstID, MetricDelay); err == nil {
				// build submodules from pathRes.Links
				psubs := make([]srEROSubobject, 0, len(pathRes.Links))
				for _, linkID := range pathRes.Links {
					if lk, ok := db.GetLink(linkID); ok {
						sid := []byte(lk.Sid)
						sl := srEROSubobject{selfType: 1, length: uint8(len(sid)), flags: 0, sid: sid}
						// attach adjacency metadata if available
						if lk != nil {
							sl.adj = []linkLocalAdj{{inf: lk.SrcNode}}
						}
						psubs = append(psubs, sl)
					}
				}
				if len(psubs) > 0 {
					sp.lspObj.header.length = uint16(len(psubs))
					sp.eroObj.submodules = psubs
				}
			}
		}
	}

	db.mu.RUnlock()

	// Attach the originating BGP update for consumers' reference.
	sp.BGPUpdate = m

	return sp
}
