package sh

import (
	"bytes"
	"testing"

	"github.com/fiorix/go-diameter/v4/diam"
	"github.com/fiorix/go-diameter/v4/diam/dict"
)

func FuzzExtractIdentity(f *testing.F) {
	// Minimal valid UDR message frame.
	udr := []byte{
		0x01, 0x00, 0x00, 0x14,
		0x80, 0x01, 0x78, 0x01, // cmd=306 UDR
		0x01, 0x00, 0x00, 0x16,
		0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x02,
	}
	f.Add(udr)
	f.Add([]byte{})
	f.Add([]byte{0x01, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	f.Fuzz(func(t *testing.T, b []byte) {
		const maxDeclared = 8 * 1024
		if len(b) < 4 {
			return
		}
		if int(b[1])<<16|int(b[2])<<8|int(b[3]) > maxDeclared {
			return
		}
		msg, err := diam.ReadMessage(bytes.NewReader(b), dict.Default)
		if err != nil {
			return
		}
		_ = extractIdentity(msg)
	})
}
