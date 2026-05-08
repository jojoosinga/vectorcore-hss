package gsup

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/svinson1121/vectorcore-hss/internal/config"
	"github.com/svinson1121/vectorcore-hss/internal/geored"
	"go.uber.org/zap"
)

// discardConn is a net.Conn whose writes go to /dev/null, used to prevent
// fuzz targets from panicking due to nil conn dereferences.
type discardConn struct{}

func (discardConn) Read(_ []byte) (int, error)        { return 0, fmt.Errorf("eof") }
func (discardConn) Write(b []byte) (int, error)        { return len(b), nil }
func (discardConn) Close() error                       { return nil }
func (discardConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (discardConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (discardConn) SetDeadline(_ time.Time) error      { return nil }
func (discardConn) SetReadDeadline(_ time.Time) error  { return nil }
func (discardConn) SetWriteDeadline(_ time.Time) error { return nil }

var fuzzGSUPServer *Server

func init() {
	fuzzGSUPServer = &Server{
		cfg:   config.GSUPConfig{Enabled: true},
		store: &mockStore{},
		log:   zap.NewNop(),
		pub:   geored.NoopTypedPublisher{},
	}
}

// FuzzGSUPHandleMessage fuzzes the GSUP message dispatch path:
// raw bytes → Decode → handleMessage.
func FuzzGSUPHandleMessage(f *testing.F) {
	// Valid AIR message.
	air := NewMsg(MsgSendAuthInfoReq).
		Add(IEIMSITag, encodeIMSI("001010000000001")).
		AddByte(IENumberOfRequestedVec, 2).
		Bytes()
	f.Add(air)

	// Valid ULR.
	ulr := NewMsg(MsgUpdateLocReq).
		Add(IEIMSITag, encodeIMSI("001010000000001")).
		AddByte(IECNDomain, CNDomainPS).
		Bytes()
	f.Add(ulr)

	// Malformed messages.
	f.Add([]byte{MsgSendAuthInfoReq, IEIMSITag, 0x00})
	f.Add([]byte{MsgUpdateLocReq})
	f.Add([]byte{MsgPurgeMSReq, IEIMSITag, 0x08, 0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60})
	f.Add([]byte{0xFF})
	f.Add([]byte{})
	f.Add(make([]byte, 256))

	conn := discardConn{}

	f.Fuzz(func(t *testing.T, b []byte) {
		msg, err := Decode(b)
		if err != nil {
			return
		}
		fuzzGSUPServer.handleMessage(conn, "fuzz-peer", ipaProtoOSMO, msg)
	})
}
