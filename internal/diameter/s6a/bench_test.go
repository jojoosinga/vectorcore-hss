package s6a

import "testing"

// Realistic 8-byte TBCD input representing the E.164 number "+12345678901".
// TBCD encoding: each nibble is one digit, low nibble first.
// "12345678901" (11 digits) → 0x21, 0x43, 0x65, 0x87, 0x09, 0xF1
// Padded to 8 bytes with 0xFF fill.
var benchTBCDBytes = []byte{0x21, 0x43, 0x65, 0x87, 0x09, 0xF1, 0xFF, 0xFF}

// Realistic MSISDN used for encodeMSISDN benchmarks.
const benchMSISDN = "12345678901"

// Realistic ULI byte slice with both TAI (flags bit 3) and ECGI (flags bit 4) present.
// Layout: flags(1) + TAI(5) + ECGI(7) = 13 bytes.
//
//   flags = 0x18  (TAI | ECGI)
//   TAI  : PLMN=31F010 (MCC=311, MNC=01), TAC=0x0001
//   ECGI : PLMN=31F010, ECI=0x0004D204 (eNodeB=0x004D2, CI=0x04)
var benchULIBytes = []byte{
	0x18,                   // flags: TAI + ECGI
	0x13, 0x1F, 0x10, 0x00, 0x01, // TAI:  PLMN(31F010) + TAC(0x0001)
	0x13, 0x1F, 0x10, 0x00, 0x4D, 0x22, 0x04, // ECGI: PLMN(31F010) + ECI
}

// BenchmarkDecodeTBCDString benchmarks decoding a packed TBCD octet string
// (the format used by Diameter AVPs such as MSISDN and MME-Number-for-MT-SMS).
func BenchmarkDecodeTBCDString(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = decodeTBCDString(benchTBCDBytes)
	}
}

// BenchmarkEncodeMSISDN benchmarks encoding a plain E.164 digit string into
// the semi-octet TBCD format written into the MSISDN Diameter AVP.
func BenchmarkEncodeMSISDN(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = encodeMSISDN(benchMSISDN)
	}
}

// BenchmarkParseULI benchmarks decoding the binary User-Location-Info AVP
// (3GPP TS 29.274 §8.22) into MCC, MNC, TAC, and ECI fields.
func BenchmarkParseULI(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = parseULI(benchULIBytes)
	}
}
