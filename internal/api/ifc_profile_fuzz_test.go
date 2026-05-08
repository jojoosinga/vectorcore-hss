package api

import "testing"

// FuzzValidateIFCProfileXMLFragment fuzzes the XML validation function used
// when creating or updating IFC profiles via the REST API.
func FuzzValidateIFCProfileXMLFragment(f *testing.F) {
	f.Add(`<InitialFilterCriteria><Priority>0</Priority></InitialFilterCriteria>`)
	f.Add(`<ifc/>`)
	f.Add(``)
	f.Add(`not xml at all`)
	f.Add(`<unclosed`)
	f.Add(`<a><b></a></b>`) // mismatched tags
	f.Add(`<?xml version="1.0"?><root/>`)
	f.Add(`<root attr="value &amp; more">text</root>`)
	f.Add(string(make([]byte, 4096)))
	f.Add(`<root>` + string([]byte{0x00, 0x01, 0x02}) + `</root>`)

	f.Fuzz(func(t *testing.T, s string) {
		// Must not panic; errors are expected for malformed input.
		_ = validateIFCProfileXML(s)
		_ = validateIFCProfileXMLFragment(s)
	})
}
