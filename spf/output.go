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

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// PathUpdate represents a computed path update for a src-dst pair with SIDs.
type PathUpdate struct {
	Src   uint32
	Dst   uint32
	SIDs  []string
	Path  []uint32
	Links []string
}

// PackPCUpd computes path updates for all node pairs and returns a slice of PathUpdate.
func PackPCUpd(s *Spf, m *bgp.BGPMessage) []PathUpdate {
	if m == nil {
		return nil
	}
	db := GetGlobalLSDB()

	var nodes []uint32
	for id := range db.Nodes {
		if db.Topology != nil {
			if _, ok := db.Topology[id]; ok {
				nodes = append(nodes, id)
				continue
			}
			included := false
			for _, targets := range db.Topology {
				if _, ok := targets[id]; ok {
					included = true
					break
				}
			}
			if included {
				nodes = append(nodes, id)
				continue
			}
		}
	}

	dupCheck := make(map[string]bool)
	var updates []PathUpdate

	for _, src := range nodes {
		for _, dst := range nodes {
			if src == dst {
				continue
			}
			if path, err := db.CalculatePath(src, dst, MetricComposite); err == nil {
				key := fmt.Sprintf("%d-%d", src, dst)
				prev, exists := s.previousPaths[key]
				if !exists || !pathsEqual(path, prev) {
					s.previousPaths[key] = path
					sids := []string{}
					for _, linkID := range path.Links {
						if link, ok := db.GetLink(linkID); ok {
							if link.Sid != "" {
								sids = append(sids, link.Sid)
							}
						}
					}
					dupKey := fmt.Sprintf("%d-%d-%v", src, dst, sids)
					if dupCheck[dupKey] {
						continue
					}
					dupCheck[dupKey] = true
					if len(sids) > 0 {
						upd := PathUpdate{
							Src:   src,
							Dst:   dst,
							SIDs:  sids,
							Path:  path.Path,
							Links: path.Links,
						}
						fmt.Printf("[SPF] PathUpdate: src=%d dst=%d sids=%v path=%v links=%v\n", upd.Src, upd.Dst, upd.SIDs, upd.Path, upd.Links)
						updates = append(updates, upd)
					}
				}
			}
		}
	}
	return updates
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
