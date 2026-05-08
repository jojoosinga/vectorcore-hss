package gsup

import "testing"

// benchULRPayload is a realistic UpdateLocationRequest GSUP payload.
// Layout: MsgUpdateLocReq | IMSI IE | CN-Domain IE
//
//   MsgUpdateLocReq = 0x04
//   IE IMSI (tag=0x01, len=8): TBCD encoding of "311435000000001"
//     31→13, 14→41, 35→53, 00→00, 00→00, 00→00, 00→00, 1→1F (padded)
//   IE CN-Domain (tag=0x0F, len=1): 0x01 (PS)
var benchULRPayload = []byte{
	MsgUpdateLocReq,
	IEIMSITag, 0x08, 0x13, 0x41, 0x53, 0x00, 0x00, 0x00, 0x00, 0x1F,
	IECNDomain, 0x01, CNDomainPS,
}

// benchAIRPayload is a realistic SendAuthInfoRequest GSUP payload.
// Layout: MsgSendAuthInfoReq | IMSI IE | NumberOfRequestedVectors IE
var benchAIRPayload = []byte{
	MsgSendAuthInfoReq,
	IEIMSITag, 0x08, 0x13, 0x41, 0x53, 0x00, 0x00, 0x00, 0x00, 0x1F,
	IENumberOfRequestedVec, 0x01, 0x02,
}

// benchIDRespPayload is a realistic IPA CCM ID_RESP payload for parseIDResp.
// Format: msg_type(0x05) | tagLen | tag | value...
// Unit-name tag (0x01) with value "osmomsc-0\x00".
var benchIDRespPayload = func() []byte {
	name := []byte("osmomsc-0\x00")
	itemLen := byte(1 + len(name)) // tag byte is included in the length
	p := make([]byte, 0, 2+len(name)+1)
	p = append(p, 0x05)      // ccmMsgIDResp
	p = append(p, itemLen)   // length of (tag + value)
	p = append(p, 0x01)      // ipaTagUnitName
	p = append(p, name...)
	return p
}()

// BenchmarkDecode benchmarks decoding a GSUP UpdateLocation request — the most
// frequent inbound message type in a live HSS (one per LTE attach).
func BenchmarkDecode(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Decode(benchULRPayload)
	}
}

// BenchmarkDecodeAIR benchmarks decoding a GSUP SendAuthInfo request, which
// carries a variable number-of-vectors IE in addition to the IMSI.
func BenchmarkDecodeAIR(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Decode(benchAIRPayload)
	}
}

// BenchmarkParseIDResp benchmarks parsing the IPA CCM ID_RESP frame that
// carries the peer unit-name during the initial IPA handshake.
func BenchmarkParseIDResp(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = parseIDResp(benchIDRespPayload)
	}
}

// BenchmarkNewMsgBuilder benchmarks building a GSUP UpdateLocationResponse —
// the most frequent outbound message type.
func BenchmarkNewMsgBuilder(b *testing.B) {
	imsi := []byte{0x13, 0x41, 0x53, 0x00, 0x00, 0x00, 0x00, 0x1F}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = NewMsg(MsgUpdateLocRes).
			Add(IEIMSITag, imsi).
			Bytes()
	}
}
