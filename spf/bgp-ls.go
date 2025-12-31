package spf

import (
	"net"
)

type ipPrefix struct {
	prefixLen uint8
	ip        net.IP
}

type pathAttribute struct {
	flags    uint8
	typeCode uint8
	length   uint16
	value    []byte
}

type BGPUpdateMessage struct {
	marker       [16]byte
	len          uint16
	myType       uint8
	wrEntriesLen uint16
	wrEntries    []ipPrefix
	pathAttrsLen uint16
	pathAttrs    []pathAttribute
	nlriEntries  []ipPrefix
}
