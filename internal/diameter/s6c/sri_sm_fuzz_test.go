package s6c

import (
	"testing"

	"github.com/fiorix/go-diameter/v4/diam/datatype"
)

func FuzzEncodeMSISDNBytes(f *testing.F) {
	f.Add("15551230001")
	f.Add("+15551230001")
	f.Add("")
	f.Add("1")
	f.Add("abc")
	f.Add("12345678901234567890")

	f.Fuzz(func(t *testing.T, s string) {
		b := encodeMSISDNBytes(s)
		if b != nil {
			// Round-trip: decode back must not panic.
			_ = decodeMSISDN(datatype.OctetString(b))
		}
	})
}

func FuzzDecodeMSISDN(f *testing.F) {
	f.Add([]byte{0x91, 0x51, 0x55, 0x12, 0x30, 0x00, 0xF1})
	f.Add([]byte{})
	f.Add([]byte{0xFF, 0xFF, 0xFF, 0xFF})
	f.Add([]byte{0x00})
	f.Add(make([]byte, 20))

	f.Fuzz(func(t *testing.T, b []byte) {
		_ = decodeMSISDN(datatype.OctetString(b))
	})
}
