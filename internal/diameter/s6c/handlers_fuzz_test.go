package s6c

import (
	"bytes"
	"testing"

	"github.com/fiorix/go-diameter/v4/diam"
	"github.com/fiorix/go-diameter/v4/diam/dict"
)

var fuzzS6cHandlers *Handlers

func init() {
	fuzzS6cHandlers = newTestHandlers(newS6cStore())
}

func s6cFuzzReadMsg(b []byte) (result *diam.Message) {
	const maxInput = 512
	const maxDeclared = 512
	if len(b) < 4 || len(b) > maxInput {
		return nil
	}
	declaredLen := int(b[1])<<16 | int(b[2])<<8 | int(b[3])
	if declaredLen < 20 || declaredLen > maxDeclared {
		return nil
	}
	defer func() {
		if r := recover(); r != nil {
			result = nil
		}
	}()
	msg, err := diam.ReadMessage(bytes.NewReader(b), dict.Default)
	if err != nil {
		return nil
	}
	return msg
}

func FuzzSRISR(f *testing.F) {
	f.Add([]byte{
		0x01, 0x00, 0x00, 0x14,
		0x80, 0x80, 0x02, 0x37, // cmd=567 SIR
		0x01, 0x00, 0x00, 0x17, // app-id S6c=16777312
		0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x02,
	})
	f.Add([]byte{})
	f.Add([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF})

	f.Fuzz(func(t *testing.T, b []byte) {
		msg := s6cFuzzReadMsg(b)
		if msg == nil {
			return
		}
		_, _ = fuzzS6cHandlers.SRISR(nil, msg)
	})
}

func FuzzRDSMR(f *testing.F) {
	f.Add([]byte{
		0x01, 0x00, 0x00, 0x14,
		0x80, 0x80, 0x04, 0x0C, // cmd=1036 RDR
		0x01, 0x00, 0x00, 0x17,
		0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x02,
	})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, b []byte) {
		msg := s6cFuzzReadMsg(b)
		if msg == nil {
			return
		}
		_, _ = fuzzS6cHandlers.RDSMR(nil, msg)
	})
}
