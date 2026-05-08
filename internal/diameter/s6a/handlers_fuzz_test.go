package s6a

import (
	"bytes"
	"testing"

	"github.com/fiorix/go-diameter/v4/diam"
	"github.com/fiorix/go-diameter/v4/diam/dict"
)

// fuzzHandlers is a shared Handlers instance for handler-level fuzz tests.
// Initialized once and reused to avoid re-loading dicts on every fuzz iteration.
var fuzzHandlers *Handlers

func init() {
	store := &s6aTestStore{}
	fuzzHandlers = newS6aTestHandlers(store)
}

func fuzzReadMsg(b []byte) *diam.Message {
	const maxDeclared = 8 * 1024
	if len(b) < 4 {
		return nil
	}
	declaredLen := int(b[1])<<16 | int(b[2])<<8 | int(b[3])
	if declaredLen > maxDeclared {
		return nil
	}
	msg, err := diam.ReadMessage(bytes.NewReader(b), dict.Default)
	if err != nil {
		return nil
	}
	return msg
}

func FuzzAIR(f *testing.F) {
	// Build seed from a valid AIR serialized with the test helpers.
	// We use a raw Diameter frame for a minimal AIR.
	f.Add([]byte{
		0x01, 0x00, 0x00, 0x14,
		0x80, 0x01, 0x3E, // cmd=318 AIR
		0x01, 0x00, 0x00, 0x23, // app-id S6a=16777251
		0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x02,
	})
	f.Add([]byte{})
	f.Add([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF})

	f.Fuzz(func(t *testing.T, b []byte) {
		msg := fuzzReadMsg(b)
		if msg == nil {
			return
		}
		_, _ = fuzzHandlers.AIR(nil, msg)
	})
}

func FuzzULR(f *testing.F) {
	f.Add([]byte{
		0x01, 0x00, 0x00, 0x14,
		0x80, 0x01, 0x36, // cmd=316 ULR
		0x01, 0x00, 0x00, 0x23,
		0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x02,
	})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, b []byte) {
		msg := fuzzReadMsg(b)
		if msg == nil {
			return
		}
		_, _ = fuzzHandlers.ULR(nil, msg)
	})
}

func FuzzPUR(f *testing.F) {
	f.Add([]byte{
		0x01, 0x00, 0x00, 0x14,
		0x80, 0x01, 0x38, // cmd=321 PUR (approximate)
		0x01, 0x00, 0x00, 0x23,
		0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x02,
	})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, b []byte) {
		msg := fuzzReadMsg(b)
		if msg == nil {
			return
		}
		_, _ = fuzzHandlers.PUR(nil, msg)
	})
}

func FuzzNOR(f *testing.F) {
	f.Add([]byte{
		0x01, 0x00, 0x00, 0x14,
		0x80, 0x01, 0x36, // reuse a valid frame shape
		0x01, 0x00, 0x00, 0x23,
		0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x02,
	})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, b []byte) {
		msg := fuzzReadMsg(b)
		if msg == nil {
			return
		}
		_, _ = fuzzHandlers.NOR(nil, msg)
	})
}
