package crypto

import (
	"encoding/hex"
	"testing"

	"github.com/svinson1121/vectorcore-hss/internal/models"
)

// Standard 3GPP TS 35.207 Test Set 1 credentials used throughout benchmarks.
const (
	benchKi  = "465b5ce8b199b49faa5f0a2ee238a6bc"
	benchOPc = "cd63cb71954a9f4e48a5994e37a02baf"
	benchAMF = "b9b9"
)

var benchPlmn = []byte{0x00, 0xF1, 0x10} // MCC=001 MNC=01

func benchStandardProfile() *models.AlgorithmProfile {
	return &models.AlgorithmProfile{
		C1: "00000000000000000000000000000000",
		C2: "00000000000000000000000000000001",
		C3: "00000000000000000000000000000002",
		C4: "00000000000000000000000000000004",
		C5: "00000000000000000000000000000008",
		R1: 64, R2: 0, R3: 32, R4: 64, R5: 96,
	}
}

// buildValidResyncInfo generates a resync payload (RAND||AUTS) that passes
// MAC-S verification for the given profile constants.  The RAND is fixed to
// the TS 35.207 Test Set 1 value so the benchmark is deterministic.
func buildValidResyncInfo(ki, opc [16]byte, sqn uint64, pc *profileConstants) ([]byte, error) {
	randArr, _ := hex.DecodeString("23553cbe9637a89d218ae64dae47bf35")
	var randB [16]byte
	copy(randB[:], randArr)

	temp, err := aesEncrypt(ki, xor16(randB, opc))
	if err != nil {
		return nil, err
	}

	// f5*: AK* = out5*[0:6]
	out5s, err := milenageFN(ki, opc, temp, pc.c5, pc.r5)
	if err != nil {
		return nil, err
	}

	sqnB := [6]byte{
		byte(sqn >> 40), byte(sqn >> 32), byte(sqn >> 24),
		byte(sqn >> 16), byte(sqn >> 8), byte(sqn),
	}
	var sqnXorAKs [6]byte
	for i := 0; i < 6; i++ {
		sqnXorAKs[i] = sqnB[i] ^ out5s[i]
	}

	// f1* with AMF=0000 → MAC-S (resync always uses zero AMF)
	_, macS, err := milenageF1(ki, opc, temp, sqn, [2]byte{0x00, 0x00}, pc.c1, pc.r1)
	if err != nil {
		return nil, err
	}

	resyncInfo := make([]byte, 30)
	copy(resyncInfo[0:16], randB[:])
	copy(resyncInfo[16:22], sqnXorAKs[:])
	copy(resyncInfo[22:30], macS[:])
	return resyncInfo, nil
}

// BenchmarkGenerateEUTRANVectorCustom benchmarks a single EUTRAN vector
// generation using a custom algorithm profile (standard Milenage constants).
// This is the hot path hit once per LTE authentication.
func BenchmarkGenerateEUTRANVectorCustom(b *testing.B) {
	ki, _ := hex.DecodeString(benchKi)
	opc, _ := hex.DecodeString(benchOPc)
	amf, _ := hex.DecodeString(benchAMF)
	pc, _ := decodeProfile(benchStandardProfile())
	sqn := uint64(0xff9bb4d0b607)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = GenerateEUTRANVectorCustom(ki, opc, amf, sqn, benchPlmn, pc)
	}
}

// BenchmarkResyncSQNFull benchmarks SQN re-synchronisation.  A valid
// resync payload is precomputed in setup so the measured path covers
// only the cryptographic work (AES + HMAC-SHA256 MAC-S verification).
func BenchmarkResyncSQNFull(b *testing.B) {
	profile := benchStandardProfile()
	auc := &models.AUC{
		Ki:  benchKi,
		OPc: benchOPc,
		AMF: benchAMF,
	}

	// Precompute a valid resync payload so each iteration succeeds.
	pc, _ := decodeProfile(profile)
	var ki, opc [16]byte
	kiB, _ := hex.DecodeString(benchKi)
	opcB, _ := hex.DecodeString(benchOPc)
	copy(ki[:], kiB)
	copy(opc[:], opcB)

	resyncInfo, err := buildValidResyncInfo(ki, opc, 0xff9bb4d0b607, pc)
	if err != nil {
		b.Fatalf("build resync info: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ResyncSQNFull(auc, profile, resyncInfo)
	}
}

// BenchmarkGenerateEAPAKAVectorCustom benchmarks a single EAP-AKA quintuplet
// generation (used for non-3GPP / SWx access authentication).
func BenchmarkGenerateEAPAKAVectorCustom(b *testing.B) {
	ki, _ := hex.DecodeString(benchKi)
	opc, _ := hex.DecodeString(benchOPc)
	amf, _ := hex.DecodeString(benchAMF)
	pc, _ := decodeProfile(benchStandardProfile())
	sqn := uint64(0xff9bb4d0b607)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = GenerateEAPAKAVectorCustom(ki, opc, amf, sqn, pc)
	}
}
