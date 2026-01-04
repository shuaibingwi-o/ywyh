// Package spf: network protocol message types used by the SPF pipeline.
package spf

import (
	"net"
)

// ipPrefix represents a network prefix (address + prefix length).
type ipPrefix struct {
	prefixLen uint8
	ip        net.IP
}

// pathAttribute represents a raw BGP path attribute.
type pathAttribute struct {
	flags    uint8
	typeCode uint8
	length   uint16
	value    []byte
}

// NLRI is an exported representation of a network-layer reachability
// information entry used when constructing test or runtime messages.
type NLRI struct {
	PrefixLen uint8
	IP        net.IP
}

// PathAttr is an exported representation of a BGP path attribute.
type PathAttr struct {
	Flags    uint8
	TypeCode uint8
	Value    []byte
}

func (n NLRI) toInternal() ipPrefix {
	return ipPrefix{prefixLen: n.PrefixLen, ip: net.IP(n.IP)}
}

func (p PathAttr) toInternal() pathAttribute {
	return pathAttribute{flags: p.Flags, typeCode: p.TypeCode, length: uint16(len(p.Value)), value: append([]byte(nil), p.Value...)}
}

// BGPUpdateMessage is a minimal representation of a BGP UPDATE message
// used as input to the SPF processing pipeline.
type BGPUpdateMessage struct {
	marker       [16]byte
	len          uint16
	selfType     uint8
	wrEntriesLen uint16
	wrEntries    []ipPrefix
	pathAttrsLen uint16
	pathAttrs    []pathAttribute
	nlriEntries  []ipPrefix
}

// AddNLRIObj appends an exported NLRI to the internal NLRI list.
func (m *BGPUpdateMessage) AddNLRIObj(n NLRI) {
	if m == nil {
		return
	}
	m.nlriEntries = append(m.nlriEntries, n.toInternal())
}

// AddPathAttrObj appends an exported PathAttr to the internal path attributes.
func (m *BGPUpdateMessage) AddPathAttrObj(p PathAttr) {
	if m == nil {
		return
	}
	m.pathAttrs = append(m.pathAttrs, p.toInternal())
	m.pathAttrsLen = uint16(len(m.pathAttrs))
}
