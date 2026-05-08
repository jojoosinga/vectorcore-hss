package sh

import "testing"

func FuzzDecodeTBCD(f *testing.F) {
	f.Add([]byte{0x10, 0x32, 0x54, 0x76, 0x98})
	f.Add([]byte{})
	f.Add([]byte{0xFF, 0xFF, 0xFF, 0xFF})
	f.Add([]byte{0x00})
	f.Add(make([]byte, 128))

	f.Fuzz(func(t *testing.T, b []byte) {
		_ = decodeTBCD(b)
	})
}

func FuzzShDecodeMSISDN(f *testing.F) {
	// TON/NPI byte (0x91 = international), then BCD digits.
	f.Add([]byte{0x91, 0x51, 0x55, 0x12, 0x30, 0x00, 0xF1})
	f.Add([]byte{})
	f.Add([]byte{0xFF})
	f.Add([]byte{0x00, 0xFF, 0xFF})
	f.Add(make([]byte, 20))

	f.Fuzz(func(t *testing.T, b []byte) {
		_ = decodeMSISDN(b)
	})
}

func FuzzNormalizePublicIdentity(f *testing.F) {
	f.Add("sip:alice@example.com")
	f.Add("tel:+15551230001")
	f.Add("alice@example.com")
	f.Add("+15551230001")
	f.Add("")
	f.Add("sip:")
	f.Add("tel:")
	f.Add(string(make([]byte, 512)))

	f.Fuzz(func(t *testing.T, s string) {
		_ = normalizePublicIdentity(s)
	})
}
