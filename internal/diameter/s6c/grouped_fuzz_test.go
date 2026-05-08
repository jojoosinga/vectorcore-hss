package s6c

import (
	"bytes"
	"testing"

	"github.com/fiorix/go-diameter/v4/diam"
	"github.com/fiorix/go-diameter/v4/diam/dict"
)

// readMsgForFuzz parses a Diameter message from raw bytes using the already-loaded
// dict (TestMain in s6c_spec_test.go loads Sh+SLh+S6c dicts).
// Returns nil if the bytes don't form a valid Diameter message or declare a huge length.
func readMsgForFuzz(b []byte) (result *diam.Message) {
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

func FuzzParseDeliveryOutcome(f *testing.F) {
	// Minimal valid RDR message (Reporting-SMSF-Delivery, cmd=8388620).
	rdr := []byte{
		0x01, 0x00, 0x00, 0x14,
		0x80, 0x80, 0x04, 0x0C,
		0x01, 0x00, 0x00, 0x17,
		0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x02,
	}
	f.Add(rdr)
	f.Add([]byte{0x01, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, b []byte) {
		const maxInput = 64 * 1024
		if len(b) > maxInput {
			return
		}
		msg := readMsgForFuzz(b)
		if msg == nil {
			return
		}
		_ = parseDeliveryOutcome(msg)
	})
}

func FuzzParseUserIdentifier(f *testing.F) {
	f.Add([]byte{
		0x01, 0x00, 0x00, 0x14,
		0x80, 0x80, 0x04, 0x0C,
		0x01, 0x00, 0x00, 0x17,
		0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x02,
	})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, b []byte) {
		const maxInput = 64 * 1024
		if len(b) > maxInput {
			return
		}
		msg := readMsgForFuzz(b)
		if msg == nil {
			return
		}
		imsi, msisdn := parseUserIdentifier(msg)
		_ = imsi
		_ = msisdn
	})
}

func FuzzExtractSMSMICorrelationID(f *testing.F) {
	f.Add([]byte{
		0x01, 0x00, 0x00, 0x14,
		0x80, 0x80, 0x04, 0x0C,
		0x01, 0x00, 0x00, 0x17,
		0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x02,
	})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, b []byte) {
		const maxInput = 64 * 1024
		if len(b) > maxInput {
			return
		}
		msg := readMsgForFuzz(b)
		if msg == nil {
			return
		}
		_ = extractSMSMICorrelationID(msg)
	})
}
