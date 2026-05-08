package gsup

import "testing"

func FuzzDecode(f *testing.F) {
	// Valid GSUP messages as seeds.
	f.Add([]byte{MsgSendAuthInfoReq, IEIMSITag, 0x08, 0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60})
	f.Add([]byte{MsgUpdateLocReq, IEIMSITag, 0x04, 0xDE, 0xAD, 0xBE, 0xEF})
	f.Add([]byte{MsgPurgeMSReq})
	f.Add([]byte{})
	f.Add([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF})
	// Truncated length field.
	f.Add([]byte{MsgSendAuthInfoReq, IEIMSITag})
	// Length overflows payload.
	f.Add([]byte{MsgSendAuthInfoReq, IEIMSITag, 0xFF, 0x01})
	// Zero-length IE.
	f.Add([]byte{MsgSendAuthInfoReq, IEIMSITag, 0x00})

	f.Fuzz(func(t *testing.T, b []byte) {
		// Must not panic; errors are expected for malformed input.
		_, _ = Decode(b)
	})
}

func FuzzEncodeDecodeIMSIRoundTrip(f *testing.F) {
	f.Add("001010000000001")
	f.Add("310260000000001")
	f.Add("0")
	f.Add("")
	f.Add("123456789012345")
	f.Add("12345678901234") // even length

	f.Fuzz(func(t *testing.T, s string) {
		// Only digit strings make sense, but we must not panic for any input.
		encoded := encodeIMSI(s)
		decoded := decodeIMSI(encoded)
		_ = decoded
	})
}
