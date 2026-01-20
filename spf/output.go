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
	"fmt"
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
// attempting path calculations for all node pairs, and returning a
// slice of `pcep.PCUpdMessage` populated with SRP and LSP information for changed paths.
func PackPCUpd(s *Spf, m *bgp.BGPMessage) []*pcep.PCUpdMessage {
	if m == nil {
		return nil
	}
	db := GetGlobalLSDB()

	// LSP length is reported as the number of links, capped at 16.
	lspLen := len(db.Links)
	if lspLen > 16 {
		lspLen = 16
	}

	// Collect all node IDs
	var nodes []uint32
	for id := range db.Nodes {
		nodes = append(nodes, id)
	}

	// Use SRP ID based on current session, increment per message per session
	if s.nextSrpIDs == nil {
		s.nextSrpIDs = make(map[uint8]uint32)
	}
	sessionID := s.CurrentSessionInfo.SessionID
	if _, ok := s.nextSrpIDs[sessionID]; !ok {
		s.nextSrpIDs[sessionID] = 0
	}

	var pcMsgs []*pcep.PCUpdMessage

	// Compute paths for all node pairs and check for changes
	for _, src := range nodes {
		for _, dst := range nodes {
			if src == dst {
				continue
			}
			if path, err := db.CalculatePath(src, dst, MetricComposite); err == nil {
				fmt.Printf("Calculated path from %d to %d: path=%+v, links=%+v\n", src, dst, path.Path, path.Links)
				key := fmt.Sprintf("%d-%d", src, dst)
				prev, exists := s.previousPaths[key]
				if !exists || !pathsEqual(path, prev) {
					// Path changed, construct PCUpd
					s.previousPaths[key] = path

					srpID := s.nextSrpIDs[sessionID]
					s.nextSrpIDs[sessionID]++
					pc := NewPCUpd(srpID, uint16(lspLen))

					sids := []string{}
					for _, linkID := range path.Links {
						if link, ok := db.GetLink(linkID); ok {
							if link.Sid != "" {
								sids = append(sids, link.Sid)
							}
						}
					}

					fmt.Printf("Path from %d to %d: %+v, links: %+v, sids: %+v\n", src, dst, path.Path, path.Links, sids)

					if len(sids) > 0 {
						// Build SRv6 ERO
						pst := &pcep.PathSetupType{PathSetupType: pcep.PathSetupTypeSRv6TE}
						srp := &pcep.SrpObject{ObjectType: pcep.ObjectTypeSRPSRP, RFlag: false, SrpID: srpID, TLVs: []pcep.TLVInterface{pst}}

						lsp, _ := pcep.NewLSPObject("", nil, 0)
						pc.SrpObject = srp
						pc.LSPObject = lsp

						ero := &pcep.EroObject{ObjectType: pcep.ObjectTypeEROExplicitRoute, EroSubobjects: []pcep.EroSubobject{}}

						var tmp pcep.SRv6EroSubobject
						segField, _ := reflect.TypeOf(tmp).FieldByName("Segment")
						segType := segField.Type

						newFn := reflect.ValueOf(pcep.NewSRv6EroSubObject)

						for _, sid := range sids {
							if a, err := netip.ParseAddr(sid); err == nil && a.Is6() {
								segVal := reflect.New(segType).Elem()
								if f := segVal.FieldByName("Sid"); f.IsValid() && f.CanSet() {
									f.Set(reflect.ValueOf(a))
								}

								res := newFn.Call([]reflect.Value{segVal})
								if !res[1].IsNil() {
									continue
								}
								subobjIface := res[0].Interface()
								if subobj, ok := subobjIface.(pcep.EroSubobject); ok {
									ero.EroSubobjects = append(ero.EroSubobjects, subobj)
								}
							}
						}

						if len(ero.EroSubobjects) > 0 {
							pc.EroObject = ero
						}
					}

					pcMsgs = append(pcMsgs, pc)
				}
			} else {
				fmt.Printf("CalculatePath from %d to %d failed: %v\n", src, dst, err)
			}
		}
	}

	return pcMsgs
}

// pathsEqual compares two PathResult for equality
func pathsEqual(p1, p2 *PathResult) bool {
	if p1 == nil || p2 == nil {
		return p1 == p2
	}
	if len(p1.Path) != len(p2.Path) || len(p1.Links) != len(p2.Links) {
		return false
	}
	for i, v := range p1.Path {
		if v != p2.Path[i] {
			return false
		}
	}
	for i, v := range p1.Links {
		if v != p2.Links[i] {
			return false
		}
	}
	return true
}
