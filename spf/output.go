// Package spf contains helpers to construct/format PCEP output messages.
package spf

import (
	"github.com/nttcom/pola/pkg/packet/pcep"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// NewPCUpd constructs a minimal PCUpd wrapper used by the SPF pipeline
// and tests. Currently the returned `PCUpd.Raw` is an empty
// `pcep.PCUpdMessage` ready to be populated by callers if desired.
func NewPCUpd(srpID uint32, lspLen uint16) *PCUpd {
	return &PCUpd{Raw: &pcep.PCUpdMessage{}, SRPID: srpID, LSPLen: lspLen}
}

// PackPCUpd handles a received BGP update by applying it to the LSDB,
// attempting a representative path calculation, and returning a
// PCUpd wrapper populated with SRP ID and LSP length (capped at 16).
func PackPCUpd(m *bgp.BGPMessage) *PCUpd {
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
	// SRv6 SIDs from link entries into a PCUpd SRv6-ERO subobject.
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

	pc := NewPCUpd(GetSRPID(m), uint16(lspLen))

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
				// Prefer embedding SRv6 SIDs in a custom TLV to avoid relying on
				// internal types and unsafe/reflect hacks. The TLV concatenates
				// 16-byte IPv6 SIDs and is defined in `spf/tlv.go`.
				pst := &pcep.PathSetupType{PathSetupType: pcep.PathSetupTypeSRv6TE}
				srp := &pcep.SrpObject{ObjectType: pcep.ObjectTypeSRPSRP, RFlag: false, SrpID: pc.SRPID, TLVs: []pcep.TLVInterface{pst}}
				tlv := &SRv6SIDListTLV{SIDs: sids}
				srp.TLVs = append(srp.TLVs, tlv)
				lsp, _ := pcep.NewLSPObject("", nil, 0)
				pc.Raw = &pcep.PCUpdMessage{SrpObject: srp, LSPObject: lsp}
			}
		}
	}

	return pc
}
