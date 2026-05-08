package s6c

import (
	"encoding/base64"
	"testing"
)

func FuzzDecodeSMSMICorrelationID(f *testing.F) {
	valid := base64.StdEncoding.EncodeToString([]byte{0x01, 0x02, 0x03, 0x04})
	f.Add(valid)
	f.Add("")
	f.Add("not-base64!!!")
	f.Add("AAAA")   // valid base64 but only 3 bytes
	f.Add("AAAAAAAAAAAAAAAAAAAA") // valid base64, 15 bytes
	f.Add(base64.StdEncoding.EncodeToString(make([]byte, 256)))

	f.Fuzz(func(t *testing.T, s string) {
		_, _ = decodeSMSMICorrelationID(&s)
	})
}
