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
	"fmt"
	"hash/fnv"
	"strconv"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// ApplyBGPUpdateToLSDB applies the provided BGP message to the
// GlobalLSDB. It returns true if the LSDB was modified.
func ApplyBGPUpdateToLSDB(m *bgp.BGPMessage) bool {
	if m == nil {
		return false
	}

	// NOTE: SRP ID maintenance removed; do not skip synthetic messages here.

	// If this is a BGP UPDATE, try to parse BGP-LS NLRI entries directly
	if upd, ok := m.Body.(*bgp.BGPUpdate); ok {
		changed := false
		for _, p := range upd.NLRI {
			// We expect p.NLRI to be an *bgp.LsAddrPrefix when this is BGP-LS
			if lp, ok := p.NLRI.(*bgp.LsAddrPrefix); ok {
				switch lp.Type {
				case bgp.LS_NLRI_TYPE_NODE:
					if nodeNLRI, ok := lp.NLRI.(*bgp.LsNodeNLRI); ok {
						if nodeNLRI.LocalNodeDesc != nil {
							if desc, ok := nodeNLRI.LocalNodeDesc.(*bgp.LsTLVNodeDescriptor); ok {
								nd := desc.Extract()
								var locator string
								if nd.BGPRouterID.IsValid() {
									locator = nd.BGPRouterID.String()
								} else if nd.IGPRouterID != "" {
									locator = nd.IGPRouterID
								} else {
									locator = fmt.Sprintf("as-%d-id-%d", nd.Asn, nd.BGPLsID)
								}
								h := fnv.New32a()
								h.Write([]byte(locator))
								id := h.Sum32()
								node := &Node{RouterId: id, Locator: locator, AsNum: nd.Asn}
								GlobalLSDB.AddNode(node)
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
							continue
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
						// 使用 local interface ID 作为链路的 key
						link := &Link{InfId: localID, SrcNode: id1, DstNode: id2, Status: true}
						// 仅使用 adjacency SID（或 peer adjacency SID）作为链路 Sid，不使用节点的 SRv6 SIDs
						for _, tlv := range linkNLRI.LinkDesc {
							switch v := tlv.(type) {
							case *bgp.LsTLVAdjacencySID:
								link.Sid = strconv.FormatUint(uint64(v.SID), 10)
								// found adjacency SID, prefer it
								break
							}
						}
						GlobalLSDB.AddLink(link)
						changed = true
					}
				}
			}
		}
		if changed {
			return true
		}
	}

	return false
}
