package s6a

import (
	"fmt"
	"testing"
)

func FuzzParseULI(f *testing.F) {
	// Well-formed TAI: type=0x80, len=7, PLMN(3 bytes), TAC(2 bytes).
	f.Add([]byte{0x80, 0x07, 0x00, 0x01, 0x10, 0x01, 0x23, 0x45, 0x00})
	// Well-formed ECGI: type=0x40, len=8, PLMN(3), ECGI(4).
	f.Add([]byte{0x40, 0x08, 0x00, 0x01, 0x10, 0x01, 0x23, 0x45, 0x67, 0x00})
	// TAI+ECGI combined (realistic ULR payload).
	f.Add([]byte{
		0x80, 0x07, 0x00, 0x01, 0x10, 0x01, 0x23, 0x45, 0x00,
		0x40, 0x08, 0x00, 0x01, 0x10, 0x01, 0x23, 0x45, 0x67, 0x00,
	})
	f.Add([]byte{})
	f.Add([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})
	// Truncated after type+length.
	f.Add([]byte{0x80, 0x07, 0x00, 0x01})
	// Length field larger than remaining bytes.
	f.Add([]byte{0x80, 0xFF, 0x00, 0x01, 0x10})

	f.Fuzz(func(t *testing.T, b []byte) {
		f, _ := parseULI(b)
		_ = fmt.Sprintf("%+v", f)
	})
}

func FuzzDecodePLMN(f *testing.F) {
	f.Add([]byte{0x00, 0x10, 0x01})  // MCC=001, MNC=01
	f.Add([]byte{0x13, 0xF0, 0x06})  // MCC=310, MNC=60
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add([]byte{0x00, 0x00})
	f.Add([]byte{0xFF, 0xFF, 0xFF})

	f.Fuzz(func(t *testing.T, b []byte) {
		mcc, mnc := decodePLMN(b)
		_ = mcc
		_ = mnc
	})
}

// TestDecodePLMN_ShortInput is the regression test for the bounds fix.
func TestDecodePLMN_ShortInput(t *testing.T) {
	for _, b := range [][]byte{nil, {}, {0x00}, {0x00, 0x01}} {
		mcc, mnc := decodePLMN(b)
		if mcc != "" || mnc != "" {
			t.Errorf("decodePLMN(%x): want empty strings, got mcc=%q mnc=%q", b, mcc, mnc)
		}
	}
}
