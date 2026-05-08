package crypto

import "testing"

// stdProfileConstants returns the standard 3GPP Milenage profile constants
// (c1=0...0, c2=1 at bit 127, etc.) as defined in TS 35.206 §3.3.
func stdProfileConstants() *profileConstants {
	var pc profileConstants
	// Standard c1: all zeros
	// Standard c2: 0x00...01 (bit 0 set)
	pc.c2[15] = 0x02
	// Standard c3: 0x00...04
	pc.c3[15] = 0x04
	// Standard c4: 0x00...08
	pc.c4[15] = 0x08
	// Standard c5: 0x00...10
	pc.c5[15] = 0x10
	// Standard r values
	pc.r1 = 8
	pc.r2 = 0
	pc.r3 = 4
	pc.r4 = 8
	pc.r5 = 4
	return &pc
}

func FuzzResyncCustom(f *testing.F) {
	validKi := make([]byte, 16)
	validOPc := make([]byte, 16)
	validResync := make([]byte, 30)

	f.Add(validKi, validOPc, validResync)
	f.Add([]byte{}, []byte{}, []byte{})
	f.Add(make([]byte, 1), make([]byte, 1), make([]byte, 1))
	f.Add(make([]byte, 16), make([]byte, 16), make([]byte, 16)) // short resync
	f.Add(make([]byte, 32), make([]byte, 32), make([]byte, 30)) // long ki/opc

	f.Fuzz(func(t *testing.T, ki, opc, resyncInfo []byte) {
		pc := stdProfileConstants()
		_, _ = ResyncCustom(ki, opc, resyncInfo, pc)
	})
}

func FuzzGenerateEUTRANVectorCustom(f *testing.F) {
	validKi := make([]byte, 16)
	validOPc := make([]byte, 16)
	validAmf := []byte{0x80, 0x00}
	validPlmn := []byte{0x00, 0x10, 0x01}

	f.Add(validKi, validOPc, validAmf, uint64(0), validPlmn)
	f.Add([]byte{}, []byte{}, []byte{}, uint64(0), []byte{})
	f.Add(make([]byte, 1), make([]byte, 1), make([]byte, 1), uint64(0), make([]byte, 1))
	f.Add(make([]byte, 32), make([]byte, 32), make([]byte, 4), uint64(^uint64(0)), make([]byte, 5))

	f.Fuzz(func(t *testing.T, ki, opc, amfB []byte, sqn uint64, plmn []byte) {
		pc := stdProfileConstants()
		_, _ = GenerateEUTRANVectorCustom(ki, opc, amfB, sqn, plmn, pc)
	})
}

func FuzzGenerateEAPAKAVectorCustom(f *testing.F) {
	validKi := make([]byte, 16)
	validOPc := make([]byte, 16)
	validAmf := []byte{0x80, 0x00}

	f.Add(validKi, validOPc, validAmf, uint64(0))
	f.Add([]byte{}, []byte{}, []byte{}, uint64(0))
	f.Add(make([]byte, 1), make([]byte, 1), make([]byte, 1), uint64(0))
	f.Add(make([]byte, 32), make([]byte, 32), make([]byte, 4), uint64(^uint64(0)))

	f.Fuzz(func(t *testing.T, ki, opc, amfB []byte, sqn uint64) {
		pc := stdProfileConstants()
		_, _ = GenerateEAPAKAVectorCustom(ki, opc, amfB, sqn, pc)
	})
}
