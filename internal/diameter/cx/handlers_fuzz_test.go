package cx

import "testing"

func FuzzEncodePLMN(f *testing.F) {
	f.Add("001", "01")
	f.Add("310", "260")
	f.Add("", "")
	f.Add("1234", "1") // too long MCC
	f.Add("abc", "de") // non-digit
	f.Add("001", "1234")
	f.Add(string(make([]byte, 64)), "01")

	f.Fuzz(func(t *testing.T, mcc, mnc string) {
		_ = encodePLMN(mcc, mnc)
	})
}

func FuzzNormalizeIMSI(f *testing.F) {
	f.Add("001010000000001@ims.mnc001.mcc001.3gppnetwork.org")
	f.Add("001010000000001")
	f.Add("")
	f.Add("@")
	f.Add("@ims.mnc001.mcc001.3gppnetwork.org")
	f.Add(string(make([]byte, 512)))

	f.Fuzz(func(t *testing.T, s string) {
		_ = normalizeIMSI(s)
	})
}

func FuzzNormalizeMSISDN(f *testing.F) {
	f.Add("tel:+15551230001")
	f.Add("tel:15551230001")
	f.Add("+15551230001")
	f.Add("15551230001")
	f.Add("")
	f.Add("tel:")
	f.Add(string(make([]byte, 256)))

	f.Fuzz(func(t *testing.T, s string) {
		_ = normalizeMSISDN(s)
	})
}
