package spf

import (
	"encoding/binary"
	"net/netip"

	"github.com/nttcom/pola/pkg/packet/pcep"
	"go.uber.org/zap/zapcore"
)

// SRv6SIDListTLV is a custom TLV used to carry a list of SRv6 SIDs
// when constructing PCUpd messages without importing pola's internal table.
type SRv6SIDListTLV struct {
	SIDs []string
}

func (t *SRv6SIDListTLV) DecodeFromBytes(data []byte) error { return nil }

func (t *SRv6SIDListTLV) Serialize() []byte {
	// value is concatenation of 16-byte IPv6 addresses
	val := []byte{}
	for _, s := range t.SIDs {
		if a, err := netip.ParseAddr(s); err == nil && a.Is6() {
			val = append(val, a.AsSlice()...)
		}
	}
	// TLV header: Type(2) + Length(2)
	tlvType := uint16(0xfff0) // local experimental TLV
	length := uint16(len(val))
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint16(hdr[0:2], tlvType)
	binary.BigEndian.PutUint16(hdr[2:4], length)
	return append(hdr, val...)
}

func (t *SRv6SIDListTLV) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	return nil
}

func (t *SRv6SIDListTLV) Type() pcep.TLVType { return pcep.TLVType(0xfff0) }

func (t *SRv6SIDListTLV) Len() uint16 { return pcep.TLVHeaderLength + uint16(16*len(t.SIDs)) }
