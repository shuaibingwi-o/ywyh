package spf

import (
	"sync"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

var (
	bgpSrpMu sync.Mutex
	bgpSrp   = make(map[*bgp.BGPMessage]uint32)
)

// Public API for constructing BGP update messages and inspecting
// SRv6Paths results.

// NewBGPUpdate creates an empty `*bgp.BGPMessage` and registers the
// provided SRP identifier so the conversion logic can preserve the
// original numeric ID used by tests/examples.
func NewBGPUpdate(srpID uint32) *bgp.BGPMessage {
	m := &bgp.BGPMessage{}
	bgpSrpMu.Lock()
	bgpSrp[m] = srpID
	bgpSrpMu.Unlock()
	return m
}

// GetSRPID returns the registered SRP identifier for a BGP message.
// It returns 0 if none is registered.
func GetSRPID(m *bgp.BGPMessage) uint32 {
	bgpSrpMu.Lock()
	defer bgpSrpMu.Unlock()
	return bgpSrp[m]
}

// (Previously SRv6Paths helpers.) Tests now use PCEP messages instead.
