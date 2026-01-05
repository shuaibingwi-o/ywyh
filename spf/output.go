// Package spf defines SRv6 path output object structures used to encode
// PCEP/PCUpd-style objects. The representations are minimal and intended
// for inter-component messaging within this project.
package spf

import (
	"github.com/nttcom/pola/pkg/packet/pcep"
)

// Rep:   |Header|RP|NOPATH|LSPA|Bandwidth|Metric|IRO[|ERO|LSPA|Bandwidth|Metric|IRO|]
// https://datatracker.ietf.org/doc/html/rfc5440#section-6.5

// PCUpd: |Header[|SRP|LSP|ERO|LSPA|Bandwidth|Metric|IRO|]
// https://datatracker.ietf.org/doc/html/rfc8231#section-6.2

// pceHeader is a small header used when constructing PCEP-like messages.
type pceHeader struct {
	verAndFlags uint8
	selfType    uint8
	len         uint16
}

// version returns the 3-bit version field from the header.
func (h *pceHeader) version() uint8 {
	return h.verAndFlags >> 5
}

// setVersion sets the 3-bit version field in the header.
func (h *pceHeader) setVersion(ver uint8) {
	h.verAndFlags = ver<<5 | (h.verAndFlags & 0x1F)
}

// flags returns the low 5 flag bits from the header.
func (h *pceHeader) flags() uint8 {
	return h.verAndFlags >> 5
}

// setFlags updates the low 5 flag bits in the header.
func (h *pceHeader) setFlags(flags uint8) {
	h.verAndFlags = h.verAndFlags&0xE0 | flags
}

// pceTLV is a generic TLV used for optional values.
type pceTLV struct {
	selfType uint16
	len      uint16
	value    []byte
}

// objectHeader is a compact object descriptor used in PCEP-like objects.
type objectHeader struct {
	objClass uint8
	objType  uint8
	length   uint16
}

// rpObject represents a Request/Report object container.
type rpObject struct {
	header    objectHeader
	requestID uint32
	pceTLVs   []pceTLV
}

// srpObject contains SRP metadata used for request/update messages.
type srpObject struct {
	header  objectHeader
	flags   uint32
	srpID   uint32
	pceTLVs []pceTLV
}

// lspObject contains minimal LSP identification and optional TLVs.
type lspObject struct {
	header     objectHeader
	plspIDmisc uint32
	pceTLVs    []pceTLV
}

// eroObject holds ERO submodules describing an explicit route.
type eroObject struct {
	header     objectHeader
	submodules []srEROSubobject
}

// lspaObject contains LSPA filtering/inclusion fields used by PCEP.
type lspaObject struct {
	header     objectHeader
	excludeAny uint32
	includeAny uint32
	inludeAll  uint32
	flags      uint32
	pceTLVs    []pceTLV
}

// bandwidthObject holds a bandwidth value.
type bandwidthObject struct {
	header   objectHeader
	bandwith uint32
}

// metricObject encodes metric-type and value.
type metricObject struct {
	header objectHeader
	rsv    uint16
	flags  uint16
	value  uint32
}

// iroObject holds an IRO value field.
type iroObject struct {
	header objectHeader
	value  []byte
}

// ipv6Addr stores an IPv6 address as 128 bits.
type ipv6Addr struct {
	address [128]byte
}

// linkLocalAdj represents a link-local adjacency (address + interface).
type linkLocalAdj struct {
	addr ipv6Addr
	inf  uint32
}

// srEROSubobject represents a single SRv6 ERO subobject with optional
// IPv6 addresses and adjacency entries.
type srEROSubobject struct {
	selfType uint8
	length   uint8
	flags    uint16
	sid      []byte
	ipv6Addr []ipv6Addr
	adj      []linkLocalAdj
}

// noPathObject encodes a NOPATH object used to indicate path absence.
type noPathObject struct {
	header objectHeader
	ni     uint8
	flags  uint16
	rsv    uint8
	value  []pceTLV
}

// ipv6Subobject is an IPv6 address subobject with a prefix length.
type ipv6Subobject struct {
	selfType  uint8
	length    uint8
	address   ipv6Addr
	prefixLen uint8
	flags     uint8
}

// SRv6Paths aggregates header plus SRP/LSP/ERO objects describing paths.
type SRv6Paths struct {
	header pceHeader
	srpObj srpObject
	lspObj lspObject
	eroObj eroObject
	// RawPCEP holds the corresponding PCEP/PCUpd external object from the
	// imported PCEP package.
	RawPCEP *pcep.PCEP
	// BGPUpdate references the originating BGP update that produced these SRv6 paths.
	BGPUpdate *BGPUpdateMessage
}
