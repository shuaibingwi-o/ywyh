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
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"reflect"
	"strconv"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// ApplyBGPUpdateToLSDB applies the provided BGP message to the
// GlobalLSDB. It returns true if the LSDB was modified.
func ApplyBGPUpdateToLSDB(m *bgp.BGPMessage) bool {
	if m == nil {
		return false
	}

	fmt.Println("ApplyBGPUpdateToLSDB called")

	// NOTE: SRP ID maintenance removed; do not skip synthetic messages here.

	// If this is a BGP UPDATE, try to parse BGP-LS NLRI entries directly
	if upd, ok := m.Body.(*bgp.BGPUpdate); ok {
		fmt.Println("Processing BGP UPDATE")
		fmt.Printf("BGPUpdate: NLRI count=%d, PathAttributes=%d\n", len(upd.NLRI), len(upd.PathAttributes))
		for i, pa := range upd.PathAttributes {
			fmt.Printf(" PathAttr[%d] type=%T\n", i, pa)
			if _, ok := pa.(*bgp.PathAttributeMpReachNLRI); ok {
				fmt.Printf("  PathAttr is MP_REACH_NLRI\n")
				fmt.Printf("  MP_REACH struct dump: %#v\n", pa)
			}
		}
		changed := false
		// Process NLRI carried directly in the Update
		for _, nlri := range upd.NLRI {
			switch n := nlri.NLRI.(type) {
			case *bgp.LsAddrPrefix:
				fmt.Printf("Processing LS NLRI type: %d\n", n.Type)
				changed = changed || processLSNLRI(n)
			}
		}

		// Also process NLRI carried inside MP_REACH_NLRI path attributes
		for _, pa := range upd.PathAttributes {
			if mp, ok := pa.(*bgp.PathAttributeMpReachNLRI); ok {
				fmt.Printf("Processing MP_REACH NLRI (AFI=0x%x, SAFI=0x%x) entries=%d\n", mp.AFI, mp.SAFI, len(mp.Value))
				for _, p := range mp.Value {
					switch n := p.NLRI.(type) {
					case *bgp.LsAddrPrefix:
						fmt.Printf("Processing LS NLRI (mp_reach) type: %d\n", n.Type)
						changed = changed || processLSNLRI(n)
					}
				}
			}
		}
		if changed {
			fmt.Println("LSDB changed")
			return true
		}
	}

	fmt.Println("LSDB not changed")
	return false
}

func processLSNLRI(lp *bgp.LsAddrPrefix) bool {
	changed := false
	switch lp.Type {
	case bgp.LS_NLRI_TYPE_NODE:
		if nodeNLRI, ok := lp.NLRI.(*bgp.LsNodeNLRI); ok {
			if nodeNLRI.LocalNodeDesc != nil {
				if desc, ok := nodeNLRI.LocalNodeDesc.(*bgp.LsTLVNodeDescriptor); ok {
					nd := desc.Extract()
					var locator string
					var id uint32
					if nd.BGPRouterID.IsValid() {
						locator = nd.BGPRouterID.String()
						// if the router ID is IPv4, use its numeric value as node id
						if nd.BGPRouterID.Is4() {
							b := nd.BGPRouterID.AsSlice()
							if len(b) == 4 {
								id = binary.BigEndian.Uint32(b)
							}
						}
					} else if nd.IGPRouterID != "" {
						locator = nd.IGPRouterID
					} else {
						locator = fmt.Sprintf("as-%d-id-%d", nd.Asn, nd.BGPLsID)
					}
					// fallback to hash if no numeric id derived
					if id == 0 {
						h := fnv.New32a()
						h.Write([]byte(locator))
						id = h.Sum32()
					}
					node := &Node{RouterId: id, Locator: locator, AsNum: nd.Asn}
					GlobalLSDB.AddNode(node)

					// Debug: try to extract TLV contents from the descriptor if available
					if LogBGPUpdates {
						fmt.Printf("Node NLRI extract: %#v\n", nd)
						// reflectively call GetLsTLV() if present
						rv := reflect.ValueOf(desc)
						m := rv.MethodByName("GetLsTLV")
						if m.IsValid() {
							res := m.Call(nil)
							if len(res) > 0 {
								rv0 := res[0]
								if rv0.IsValid() {
									switch rv0.Kind() {
									case reflect.Ptr, reflect.Map, reflect.Slice, reflect.Chan, reflect.Func, reflect.Interface:
										if !rv0.IsNil() {
											tlv := rv0.Interface()
											fmt.Printf("Node descriptor TLV: %T %#v\n", tlv, tlv)
										}
									default:
										// non-nil value (struct, basic types, etc.)
										tlv := rv0.Interface()
										fmt.Printf("Node descriptor TLV: %T %#v\n", tlv, tlv)
									}
								}
							}
						}
					}

					// If this NLRI carries a BGPLsID, register it
					// as the SRP identifier for this BGP message so
					// downstream packaging can use it.
					if nd.BGPLsID != 0 {
						// TODO: consider registering BGPLsID per session if needed.
						// Currently SRP ID handling is disabled and defaults to 0.
					}
					changed = true
				}
			}
		}

	case bgp.LS_NLRI_TYPE_LINK:
		if linkNLRI, ok := lp.NLRI.(*bgp.LsLinkNLRI); ok {
			// Extract local/remote identifiers
			var localID, remoteID string
			// prefer interface IPv6 addresses if present
			ld := &bgp.LsLinkDescriptor{}
			ld.ParseTLVs(linkNLRI.LinkDesc)
			if ld.InterfaceAddrIPv6 != nil {
				localID = ld.InterfaceAddrIPv6.String()
			}
			if ld.NeighborAddrIPv6 != nil {
				remoteID = ld.NeighborAddrIPv6.String()
			}
			// fallback to BGP router IDs from node descriptors
			if localID == "" && linkNLRI.LocalNodeDesc != nil {
				if d, ok := linkNLRI.LocalNodeDesc.(*bgp.LsTLVNodeDescriptor); ok {
					localID = d.Extract().BGPRouterID.String()
				}
			}
			if remoteID == "" && linkNLRI.RemoteNodeDesc != nil {
				if d, ok := linkNLRI.RemoteNodeDesc.(*bgp.LsTLVNodeDescriptor); ok {
					remoteID = d.Extract().BGPRouterID.String()
				}
			}
			if localID == "" && remoteID == "" {
				// nothing usable
				return false
			}
			if localID == "" {
				localID = remoteID + "-local"
			}
			if remoteID == "" {
				remoteID = localID + "-remote"
			}
			h1 := fnv.New32a()
			h1.Write([]byte(localID))
			id1 := h1.Sum32()
			h2 := fnv.New32a()
			h2.Write([]byte(remoteID))
			id2 := h2.Sum32()
			GlobalLSDB.AddNode(&Node{RouterId: id1, Locator: localID})
			GlobalLSDB.AddNode(&Node{RouterId: id2, Locator: remoteID})
			// 使用 local interface ID 作为链路的 key，创建两个单向链路（local->remote, remote->local）
			// 从 TLV 中分别提取 adjacency SID 与 peer-adjacency SID
			var sidFwd, sidRev string
			for _, tlv := range linkNLRI.LinkDesc {
				switch v := tlv.(type) {
				case *bgp.LsTLVAdjacencySID:
					sidFwd = strconv.FormatUint(uint64(v.SID), 10)
				case *bgp.LsTLVPeerAdjacencySID:
					sidRev = strconv.FormatUint(uint64(v.SID), 10)
				}
			}

			// forward: local -> remote
			linkF := &Link{InfId: localID, SrcNode: id1, DstNode: id2, Status: true, Sid: sidFwd}
			// reverse: remote -> local
			linkR := &Link{InfId: remoteID, SrcNode: id2, DstNode: id1, Status: true, Sid: sidRev}

			GlobalLSDB.AddLink(linkF)
			GlobalLSDB.AddLink(linkR)
			changed = true
		}
	}
	return changed
}
