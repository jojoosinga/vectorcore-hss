package s6a

import "testing"

func FuzzDecodeTBCDString(f *testing.F) {
	f.Add([]byte{0x10, 0x32, 0x54, 0x76, 0x98, 0xF0}) // 12345678901 encoded
	f.Add([]byte{})
	f.Add([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})
	f.Add([]byte{0x00})
	f.Add(make([]byte, 256)) // large input

	f.Fuzz(func(t *testing.T, b []byte) {
		_ = decodeTBCDString(b)
	})
}

func FuzzEncodeMSISDN(f *testing.F) {
	f.Add("15551230001")
	f.Add("+15551230001")
	f.Add("")
	f.Add("1")
	f.Add("12345678901234") // 14 digits — even
	f.Add("123456789012345") // 15 digits — odd
	f.Add("abc")             // non-digit
	f.Add("123456789012345678901234567890") // very long

	f.Fuzz(func(t *testing.T, s string) {
		b, _ := encodeMSISDN(s)
		if b != nil {
			// Round-trip: decode back; result must not panic.
			_ = decodeTBCDString(b)
		}
	})
}
