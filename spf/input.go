package spf

import (
	"fmt"
	"hash/fnv"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// ApplyBGPUpdateToLSDB applies the provided BGP message to the
// GlobalLSDB. It returns true if the LSDB was modified.
func ApplyBGPUpdateToLSDB(m *bgp.BGPMessage) bool {
	if m == nil {
		return false
	}

	bgpSrpMu.Lock()
	_, synthetic := bgpSrp[m]
	bgpSrpMu.Unlock()
	if synthetic {
		return false
	}

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
									bgpSrpMu.Lock()
									bgpSrp[m] = uint32(nd.BGPLsID)
									bgpSrpMu.Unlock()
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
						inf := fmt.Sprintf("ls-link-%d-%d", id1, id2)
						link := &Link{InfId: inf, SrcNode: id1, DstNode: id2, Status: true}
						GlobalLSDB.AddLink(link)
						changed = true
					}

				case bgp.LS_NLRI_TYPE_SRV6_SID:
					if srv6NLRI, ok := lp.NLRI.(*bgp.LsSrv6SIDNLRI); ok {
						if srv6NLRI.LocalNodeDesc != nil && srv6NLRI.Srv6SIDInfo != nil {
							if desc, ok := srv6NLRI.LocalNodeDesc.(*bgp.LsTLVNodeDescriptor); ok {
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
								// Ensure node exists
								GlobalLSDB.AddNode(&Node{RouterId: id, Locator: locator, AsNum: nd.Asn})
								// Register BGPLsID as SRP identifier when present.
								if nd.BGPLsID != 0 {
									bgpSrpMu.Lock()
									bgpSrp[m] = uint32(nd.BGPLsID)
									bgpSrpMu.Unlock()
								}
								// Extract SIDs
								if sInfo, ok := srv6NLRI.Srv6SIDInfo.(*bgp.LsTLVSrv6SIDInfo); ok {
									sids := []string{}
									for _, a := range sInfo.SIDs {
										if a.Is6() {
											sids = append(sids, a.String())
										}
									}
									if len(sids) > 0 {
										// Append SIDs to node entry (avoid duplicates)
										if node, exists := GlobalLSDB.GetNode(id); exists {
											existMap := map[string]bool{}
											for _, v := range node.SRv6SIDs {
												existMap[v] = true
											}
											for _, sid := range sids {
												if !existMap[sid] {
													node.SRv6SIDs = append(node.SRv6SIDs, sid)
												}
											}
											GlobalLSDB.AddNode(node)
										}
									}
								}
								changed = true
							}
						}
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
