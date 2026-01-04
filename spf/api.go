package spf

import "net"

// Public API for constructing BGP update messages and inspecting
// SRv6Paths results.

// NewBGPUpdate constructs a minimal BGPUpdateMessage with the internal
// length field set. Use the provided setter methods to populate other
// fields such as marker, selfType, NLRI entries, and path attributes.
func NewBGPUpdate(length uint16) BGPUpdateMessage {
	return BGPUpdateMessage{len: length}
}

// SetLength updates the internal length field of the message.
func (m *BGPUpdateMessage) SetLength(length uint16) {
	if m == nil {
		return
	}
	m.len = length
}

// SetMarker sets the 16-byte marker field used by the internal message
// representation.
func (m *BGPUpdateMessage) SetMarker(marker [16]byte) {
	if m == nil {
		return
	}
	m.marker = marker
}

// SetSelfType sets the internal selfType field on the message.
func (m *BGPUpdateMessage) SetSelfType(t uint8) {
	if m == nil {
		return
	}
	m.selfType = t
}

// AddNLRI appends a network-layer reachability information entry to the
// message. The IP argument is interpreted as a raw IP address (v4 or v6).
func (m *BGPUpdateMessage) AddNLRI(prefixLen uint8, ip []byte) {
	if m == nil {
		return
	}
	m.nlriEntries = append(m.nlriEntries, ipPrefix{prefixLen: prefixLen, ip: net.IP(ip)})
}

// AddPathAttribute appends a raw path attribute to the message. The
// caller provides flags, type code and value bytes.
func (m *BGPUpdateMessage) AddPathAttribute(flags uint8, typeCode uint8, value []byte) {
	if m == nil {
		return
	}
	pa := pathAttribute{flags: flags, typeCode: typeCode, length: uint16(len(value)), value: append([]byte(nil), value...)}
	m.pathAttrs = append(m.pathAttrs, pa)
	m.pathAttrsLen = uint16(len(m.pathAttrs))
}

// SRPID returns the SRP ID contained in the SRv6Paths result.
func (p SRv6Paths) SRPID() uint32 {
	return p.srpObj.srpID
}

// LSPLength returns the LSP length from the SRv6Paths result.
func (p SRv6Paths) LSPLength() uint16 {
	return p.lspObj.header.length
}
