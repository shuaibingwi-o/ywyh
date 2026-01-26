// SPDX-License-Identifier: http://www.apache.org/licenses/LICENSE-2.0
/*
 *
 * Copyright (C) 2026 , Inc.
 *
 * Authors:
 *
 */

package spf

import (
	"context"
	"os"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// SessionInfo holds session and request identifiers.
type SessionInfo struct {
	SessionID uint8
	RequestID uint32
}

// End of SessionInfo struct

// Spf holds the pipeline channels and context.
type Spf struct {
	ctx                context.Context
	cancel             context.CancelFunc
	BgpUpdates         chan *bgp.BGPMessage
	SrPaths            chan []PathUpdate
	CurrentSessionInfo SessionInfo
	nextSrpIDs         map[uint8]uint32
	previousPaths      map[string]*PathResult // key: src-dst, value: previous path
}

// Logging toggles (can be set by consumers)
var (
	LogBGPUpdates = true
	LogPCUpdMsgs  = true
)

// NewSpf creates a new Spf instance with provided buffer sizes.
func NewSpf(bufIn, bufOut int) *Spf {
	ctx, cancel := context.WithCancel(context.Background())
	return &Spf{
		ctx:                ctx,
		cancel:             cancel,
		BgpUpdates:         make(chan *bgp.BGPMessage, bufIn),
		SrPaths:            make(chan []PathUpdate, bufOut),
		CurrentSessionInfo: SessionInfo{},
		nextSrpIDs:         make(map[uint8]uint32),
		previousPaths:      make(map[string]*PathResult),
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
			changed := ApplyBGPUpdateToLSDB(m)
			if !changed {
				continue
			}
			updates := PackPCUpd(s, m)
			if len(updates) > 0 {
				select {
				case s.SrPaths <- updates:
				case <-s.ctx.Done():
					return
				}
			}
		}
	}
}

// Stop cancels processing and persists the LSDB.
func (s *Spf) Stop() {
	s.cancel()
	SaveLSDB(GetGlobalLSDB())
}
