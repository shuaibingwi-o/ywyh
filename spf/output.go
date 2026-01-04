package spf

// Rep:   |Header|RP|NOPATH|LSPA|Bandwidth|Metric|IRO[|ERO|LSPA|Bandwidth|Metric|IRO|]
// https://datatracker.ietf.org/doc/html/rfc5440#section-6.5

// PCUpd: |Header[|SRP|LSP|ERO|LSPA|Bandwidth|Metric|IRO|]
// https://datatracker.ietf.org/doc/html/rfc8231#section-6.2

type pceHeader struct {
	verAndFlags uint8
	selfType    uint8
	len         uint16
}

func (h *pceHeader) version() uint8 {
	return h.verAndFlags >> 5
}

func (h *pceHeader) setVersion(ver uint8) {
	h.verAndFlags = ver<<5 | (h.verAndFlags & 0x1F)
}

func (h *pceHeader) flags() uint8 {
	return h.verAndFlags >> 5
}

func (h *pceHeader) setFlags(flags uint8) {
	h.verAndFlags = h.verAndFlags&0xE0 | flags
}

type pceTLV struct {
	selfType uint16
	len      uint16
	value    []byte
}

type objectHeader struct {
	objClass uint8
	objType  uint8
	length   uint16
}

type rpObject struct {
	header    objectHeader
	requestID uint32
	pceTLVs   []pceTLV
}

type srpObject struct {
	header  objectHeader
	flags   uint32
	srpID   uint32
	pceTLVs []pceTLV
}

type lspObject struct {
	header     objectHeader
	plspIDmisc uint32
	pceTLVs    []pceTLV
}

type eroObject struct {
	header     objectHeader
	submodules []srEROSubobject
}

type lspaObject struct {
	header     objectHeader
	excludeAny uint32
	includeAny uint32
	inludeAll  uint32
	flags      uint32
	pceTLVs    []pceTLV
}

type bandwidthObject struct {
	header   objectHeader
	bandwith uint32
}
type metricObject struct {
	header objectHeader
	rsv    uint16
	flags  uint16
	value  uint32
}

type iroObject struct {
	header objectHeader
	value  []byte
}

type ipv6Addr struct {
	address [128]byte
}

type linkLocalAdj struct {
	addr ipv6Addr
	inf  uint32
}

type srEROSubobject struct {
	selfType uint8
	length   uint8
	flags    uint16
	sid      []byte
	ipv6Addr []ipv6Addr
	adj      []linkLocalAdj
}

type noPathObject struct {
	header objectHeader
	ni     uint8
	flags  uint16
	rsv    uint8
	value  []pceTLV
}

type ipv6Subobject struct {
	selfType  uint8
	length    uint8
	address   ipv6Addr
	prefixLen uint8
	flags     uint8
}

type SRv6Paths struct {
	header pceHeader
	srpObj srpObject
	lspObj lspObject
	eroObj eroObject
}
