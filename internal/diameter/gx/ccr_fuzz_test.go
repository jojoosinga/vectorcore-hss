package gx

import "testing"

func FuzzApplyTFTHandling(f *testing.F) {
	f.Add("permit out ip from any to assigned", "standard")
	f.Add("permit out ip from any to assigned", "flip-permit-in")
	f.Add("permit in ip from any to any", "standard")
	f.Add("permit in ip from any to any", "flip-permit-in")
	f.Add("", "standard")
	f.Add("", "")
	f.Add("deny out tcp from 192.168.0.0/16 80 to any", "flip-permit-in")
	f.Add(string(make([]byte, 1024)), "standard")

	f.Fuzz(func(t *testing.T, tft, mode string) {
		_, _ = ApplyTFTHandling(tft, mode)
	})
}

func FuzzShouldRewritePermitInTFT(f *testing.F) {
	f.Add("permit in ip from any to assigned", "flip-permit-in")
	f.Add("permit out ip from any to assigned", "flip-permit-in")
	f.Add("permit in ip from any to any", "standard")
	f.Add("", "standard")
	f.Add(string(make([]byte, 512)), "flip-permit-in")

	f.Fuzz(func(t *testing.T, tft, mode string) {
		_ = shouldRewritePermitInTFT(tft, mode)
	})
}

func FuzzSplitTrim(f *testing.F) {
	f.Add("permit out ip from any to assigned")
	f.Add("  spaces   everywhere  ")
	f.Add("")
	f.Add("\t\n\r")
	f.Add(string(make([]byte, 2048)))

	f.Fuzz(func(t *testing.T, s string) {
		_ = splitTrim(s)
	})
}

func FuzzStripAPNFQDN(f *testing.F) {
	f.Add("internet.mnc001.mcc311.gprs")
	f.Add("internet")
	f.Add("")
	f.Add("a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p")
	f.Add(string(make([]byte, 256)))

	f.Fuzz(func(t *testing.T, s string) {
		_ = stripAPNFQDN(s)
	})
}
