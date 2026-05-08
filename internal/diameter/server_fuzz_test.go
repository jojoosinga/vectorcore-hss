package diameter

import (
	"bytes"
	"sync"
	"testing"

	"github.com/fiorix/go-diameter/v4/diam"
	"github.com/fiorix/go-diameter/v4/diam/datatype"
	"github.com/fiorix/go-diameter/v4/diam/dict"

	"github.com/svinson1121/vectorcore-hss/internal/diameter/basedict"
)

var dictOnce sync.Once

func initDicts(t testing.TB) {
	dictOnce.Do(func() {
		// Load only the base 3GPP dict for FuzzReadMessage.  Per-app dicts
		// (s13, cx, sh, …) are loaded in the handler-level fuzz tests within
		// each sub-package where they are needed.  Loading all 11 dicts in
		// every fuzz worker process causes OOM on constrained machines.
		if err := basedict.Load(); err != nil {
			t.Logf("dict load warning: %v", err)
		}
	})
}

func FuzzReadMessage(f *testing.F) {
	initDicts(f)

	// Seed with syntactically valid Diameter messages (minimal frames).
	// CER: version=1, length=20, flags=0x80, cmd=257, appID=0, hopByHop=1, endToEnd=2.
	f.Add([]byte{
		0x01, 0x00, 0x00, 0x14, // version=1, length=20
		0x80, 0x01, 0x01,       // flags=0x80(Request), cmd=257 (CER)
		0x00, 0x00, 0x00, 0x00, // app-id=0
		0x00, 0x00, 0x00, 0x01, // hop-by-hop
		0x00, 0x00, 0x00, 0x02, // end-to-end
	})
	// AIR: cmd=318
	f.Add([]byte{
		0x01, 0x00, 0x00, 0x14,
		0x80, 0x01, 0x3E,
		0x01, 0x00, 0x00, 0x23,
		0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x02,
	})
	// Completely random bytes.
	f.Add([]byte{0x00, 0x00, 0x00, 0x00})
	f.Add([]byte{})
	f.Add([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF})
	// Truncated message.
	f.Add([]byte{0x01, 0x00, 0x01, 0x00})
	// Message with huge declared length.
	f.Add([]byte{0x01, 0xFF, 0xFF, 0xFF, 0x00, 0x01, 0x01, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x02})

	f.Fuzz(func(t *testing.T, b []byte) {
		// The Diameter message length is declared in bytes 1-3 of the header.
		// A malicious input can declare a huge length even if the payload is tiny,
		// causing the library to attempt a large allocation.  Cap both the raw
		// input size AND the declared message length to avoid OOM.
		const maxDeclared = 8 * 1024 // 8 KiB — more than enough for any valid test msg
		if len(b) < 4 {
			return
		}
		declaredLen := int(b[1])<<16 | int(b[2])<<8 | int(b[3])
		if declaredLen > maxDeclared {
			return
		}

		msg, err := diam.ReadMessage(bytes.NewReader(b), dict.Default)
		if err != nil {
			return
		}

		// Exercise the header unmarshal used by the wrap() function in server.go.
		var hdr struct {
			OriginHost datatype.DiameterIdentity `avp:"Origin-Host"`
		}
		_ = msg.Unmarshal(&hdr)
	})
}
