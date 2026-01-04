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
