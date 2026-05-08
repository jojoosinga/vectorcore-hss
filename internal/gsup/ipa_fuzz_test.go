package gsup

import "testing"

func FuzzParseIDResp(f *testing.F) {
	// Normal ID_RESP: msg-type byte, then (tagLen, tag, value...) tuples.
	// tagLen includes the tag byte itself, so tagLen=5 means 1 byte tag + 4 bytes value.
	f.Add([]byte{ccmMsgIDResp, 0x05, ipaTagUnitName, 'h', 's', 's', '1'})
	f.Add([]byte{ccmMsgIDResp, 0x01, ipaTagUnitName})
	f.Add([]byte{ccmMsgIDResp})
	f.Add([]byte{})
	// tagLen == 0 — previously caused a slice-out-of-range panic.
	f.Add([]byte{ccmMsgIDResp, 0x00, ipaTagUnitName})
	// tagLen == 1 (tag only, no value).
	f.Add([]byte{ccmMsgIDResp, 0x01, ipaTagUnitID})
	// Very large tagLen.
	f.Add([]byte{ccmMsgIDResp, 0xFF, ipaTagUnitName, 0x01, 0x02})
	// Multiple TLVs.
	f.Add([]byte{ccmMsgIDResp,
		0x03, ipaTagSerial, 'A', 'B',
		0x05, ipaTagUnitName, 'h', 's', 's', '1',
	})

	f.Fuzz(func(t *testing.T, b []byte) {
		// Must not panic for any byte sequence.
		_ = parseIDResp(b)
	})
}

// TestParseIDResp_ZeroTagLen is the regression test for the panic fixed in parseIDResp.
func TestParseIDResp_ZeroTagLen(t *testing.T) {
	// tagLen == 0 must not panic and must return the empty string.
	result := parseIDResp([]byte{ccmMsgIDResp, 0x00, ipaTagUnitName})
	if result != "" {
		t.Errorf("expected empty string, got %q", result)
	}
}
