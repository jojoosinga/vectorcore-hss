package crypto

import (
	"testing"

	"github.com/svinson1121/vectorcore-hss/internal/models"
)

// FuzzResyncSQNFull fuzzes the standard-library path of ResyncSQNFull using a
// fixed well-formed AUC and varying the resyncInfo bytes.
// This exercises the emakeev/milenage library's GenerateResync path.
func FuzzResyncSQNFull(f *testing.F) {
	validAUC := &models.AUC{
		Ki:  "000102030405060708090a0b0c0d0e0f",
		OPc: "63bfa50ee6523365ff14c1f45f88737d",
		AMF: "8000",
	}

	f.Add(make([]byte, 30))
	f.Add([]byte{})
	f.Add(make([]byte, 16))
	f.Add(make([]byte, 29))
	f.Add(make([]byte, 31))
	f.Add(make([]byte, 1024))

	f.Fuzz(func(t *testing.T, resyncInfo []byte) {
		_, _ = ResyncSQNFull(validAUC, nil, resyncInfo)
	})
}

// FuzzResyncSQNFullBadKeys tests that badly-formed Ki/OPc are rejected cleanly.
func FuzzResyncSQNFullBadKeys(f *testing.F) {
	f.Add("", "", "8000", make([]byte, 30))
	f.Add("ZZZZ", "ZZZZ", "8000", make([]byte, 30))
	f.Add("0001020304050607", "0001020304050607", "8000", make([]byte, 30)) // 8 bytes each
	f.Add("000102030405060708090a0b0c0d0e0f00", // 17 bytes
		"63bfa50ee6523365ff14c1f45f88737d",
		"8000",
		make([]byte, 30))

	f.Fuzz(func(t *testing.T, ki, opc, amf string, resyncInfo []byte) {
		auc := &models.AUC{Ki: ki, OPc: opc, AMF: amf}
		_, _ = ResyncSQNFull(auc, nil, resyncInfo)
	})
}
