// SPDX-License-Identifier: http://www.apache.org/licenses/LICENSE-2.0
/*
 *
 * Copyright (C) 2026 , Inc.
 *
 * Authors:
 *
 */

// Package spf contains helpers to construct/format PCEP output messages.
package spf

import (
	"net/netip"
	"reflect"

	"github.com/nttcom/pola/pkg/packet/pcep"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// NewPCUpd constructs a minimal `pcep.PCUpdMessage` with provided SRP ID.
func NewPCUpd(srpID uint32, lspLen uint16) *pcep.PCUpdMessage {
	return &pcep.PCUpdMessage{SrpObject: &pcep.SrpObject{SrpID: srpID}}
}

// PackPCUpd handles a received BGP update by applying it to the LSDB,
// attempting a representative path calculation, and returning a
// `pcep.PCUpdMessage` populated with SRP and LSP information.
func PackPCUpd(s *Spf, m *bgp.BGPMessage) *pcep.PCUpdMessage {
	if m == nil {
		return nil
	}
	db := GetGlobalLSDB()

	// LSP length is reported as the number of links, capped at 16.
	lspLen := len(db.Links)
	if lspLen > 16 {
		lspLen = 16
	}

	// Try to compute a representative path (best-effort) and embed
	// SRv6 SIDs from link entries into the PCUpd ERO or TLVs.
	var src, dst uint32
	for id := range db.Nodes {
		if src == 0 {
			src = id
			continue
		}
		if dst == 0 && id != src {
			dst = id
			break
		}
	}

	// Use SRP ID based on current session, increment per message per session
	if s.nextSrpIDs == nil {
		s.nextSrpIDs = make(map[uint8]uint32)
	}
	sessionID := s.CurrentSessionInfo.SessionID
	if _, ok := s.nextSrpIDs[sessionID]; !ok {
		s.nextSrpIDs[sessionID] = 0
	}
	srpID := (uint32(sessionID) << 12) | s.nextSrpIDs[sessionID]
	s.nextSrpIDs[sessionID]++
	pc := NewPCUpd(srpID, uint16(lspLen))

	// Compute representative path and collect SRv6 SIDs from the LSDB links.
	if src != 0 && dst != 0 {
		if path, err := db.CalculatePath(src, dst, MetricComposite); err == nil {
			sids := []string{}
			for _, linkID := range path.Links {
				if link, ok := db.GetLink(linkID); ok {
					if link.Sid != "" {
						sids = append(sids, link.Sid)
					}
				}
			}

			if len(sids) > 0 {
				// Build an SRv6 ERO (explicit route) using pcep's SRv6 subobject
				// implementation. We construct values of the concrete segment type
				// via reflection so we don't need to import pola's internal package.
				pst := &pcep.PathSetupType{PathSetupType: pcep.PathSetupTypeSRv6TE}
				srp := &pcep.SrpObject{ObjectType: pcep.ObjectTypeSRPSRP, RFlag: false, SrpID: srpID, TLVs: []pcep.TLVInterface{pst}}

				lsp, _ := pcep.NewLSPObject("", nil, 0)
				pc.SrpObject = srp
				pc.LSPObject = lsp

				// Prepare ERO object and append SRv6 subobjects created reflectively
				ero := &pcep.EroObject{ObjectType: pcep.ObjectTypeEROExplicitRoute, EroSubobjects: []pcep.EroSubobject{}}

				// Helper: obtain the concrete SegmentSRv6 type via the SRv6EroSubobject's Segment field
				var tmp pcep.SRv6EroSubobject
				segField, _ := reflect.TypeOf(tmp).FieldByName("Segment")
				segType := segField.Type

				// Constructor function reference
				newFn := reflect.ValueOf(pcep.NewSRv6EroSubObject)

				for _, sid := range sids {
					if a, err := netip.ParseAddr(sid); err == nil && a.Is6() {
						segVal := reflect.New(segType).Elem()
						// Set common fields expected by pcep.SRv6EroSubobject serialization
						if f := segVal.FieldByName("Sid"); f.IsValid() && f.CanSet() {
							f.Set(reflect.ValueOf(a))
						}
						// LocalAddr/RemoteAddr left as zero (invalid) unless needed

						// Call pcep.NewSRv6EroSubObject(seg)
						res := newFn.Call([]reflect.Value{segVal})
						if !res[1].IsNil() {
							// skip on error
							continue
						}
						subobjIface := res[0].Interface()
						if subobj, ok := subobjIface.(pcep.EroSubobject); ok {
							ero.EroSubobjects = append(ero.EroSubobjects, subobj)
						}
					}
				}

				// Attach ERO only if we built subobjects
				if len(ero.EroSubobjects) > 0 {
					pc.EroObject = ero
				}
			}
		}
	}

	return pc
}
