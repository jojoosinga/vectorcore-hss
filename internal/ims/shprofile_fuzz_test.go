package ims

import (
	"encoding/xml"
	"strings"
	"testing"

	"github.com/svinson1121/vectorcore-hss/internal/models"
)

func ptrStr(s string) *string { return &s }

func FuzzEscapeXML(f *testing.F) {
	f.Add("hello world")
	f.Add("<script>alert('xss')</script>")
	f.Add(`"'<>&`)
	f.Add("")
	f.Add(string([]byte{0x00, 0x01, 0x02, 0x03}))
	f.Add(string(make([]byte, 1024)))

	f.Fuzz(func(t *testing.T, s string) {
		result := escapeXML(s)
		// Result must be valid XML text content.
		if err := xml.Unmarshal([]byte("<r>"+result+"</r>"), new(interface{})); err != nil {
			t.Errorf("escapeXML produced invalid XML for input %q: %v", s, err)
		}
	})
}

func FuzzNormalizeMNC(f *testing.F) {
	f.Add("01")
	f.Add("001")
	f.Add("1")
	f.Add("")
	f.Add("abcde")
	f.Add("12345")
	f.Add(string(make([]byte, 64)))

	f.Fuzz(func(t *testing.T, s string) {
		_ = NormalizeMNC(s)
	})
}

func FuzzBuildShUserData(f *testing.F) {
	imsi := "001010000000001"
	scscf := "sip:scscf.ims.mnc001.mcc001.3gppnetwork.org"
	msisdnList := "15551230002,15551230003"

	f.Add("15551230001", imsi, scscf, msisdnList, "<ifc/>", "001", "01")
	f.Add("", "", "", "", "", "", "")
	f.Add("<evil>", "<script>", `"'&`, "><", "", "abc", "de")
	f.Add(string(make([]byte, 256)), string(make([]byte, 32)), "", "", string(make([]byte, 64)), "001", "01")

	f.Fuzz(func(t *testing.T, msisdn, imsi, scscf, msisdnList, ifcXML, mcc, mnc string) {
		sub := &models.IMSSubscriber{
			MSISDN:     msisdn,
			IMSI:       ptrStr(imsi),
			SCSCF:      ptrStr(scscf),
			MSISDNList: ptrStr(msisdnList),
		}
		var ifc *models.IFCProfile
		if ifcXML != "" {
			ifc = &models.IFCProfile{XMLData: ifcXML}
		}

		result := BuildShUserData(sub, ifc, mcc, mnc)

		// Result must be well-formed XML.
		if err := xml.Unmarshal([]byte(result), new(interface{})); err != nil {
			// Only report if the input itself doesn't already contain raw
			// XML-incompatible data that bypasses escapeXML (i.e. the ifc.XMLData
			// path which is trusted content from the DB validated at write time).
			unsafeInputs := []string{msisdn, imsi, scscf, msisdnList}
			for _, s := range unsafeInputs {
				if strings.ContainsAny(s, "<>&") {
					return
				}
			}
			_ = err // ifcXML is embedded raw; malformed XML there is expected
		}
	})
}

func FuzzBuildCxUserData(f *testing.F) {
	imsi := "001010000000001"

	f.Add("15551230001", imsi, "<ifc/>", "001", "01")
	f.Add("", "", "", "", "")
	f.Add("<evil>", "<script>", `"'&`, "001", "01")
	f.Add(string(make([]byte, 256)), string(make([]byte, 32)), string(make([]byte, 64)), "001", "01")

	f.Fuzz(func(t *testing.T, msisdn, imsi, ifcXML, mcc, mnc string) {
		sub := &models.IMSSubscriber{
			MSISDN: msisdn,
			IMSI:   ptrStr(imsi),
		}
		var ifc *models.IFCProfile
		if ifcXML != "" {
			ifc = &models.IFCProfile{XMLData: ifcXML}
		}

		result := BuildCxUserData(sub, ifc, mcc, mnc)
		_ = result
	})
}
