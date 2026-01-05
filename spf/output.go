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

	// Try to compute a representative path (best-effort). We don't
	// currently embed the path into the PCUpd, but path computation
	// is performed to preserve previous behavior and side-effects.
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
	if src != 0 && dst != 0 {
		if _, _err := db.CalculatePath(src, dst, MetricDelay); _err == nil {
			// ignore returned path; presence of a path is sufficient
		}
	}

	return NewPCUpd(GetSRPID(m), uint16(lspLen))
}
