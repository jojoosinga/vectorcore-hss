package config

import (
	"os"
	"testing"
)

var validConfig []byte

func init() {
	b, err := os.ReadFile("../../bin/config.yaml")
	if err == nil {
		validConfig = b
	}
}

func FuzzLoadFromBytes(f *testing.F) {
	if len(validConfig) > 0 {
		f.Add(validConfig)
	}

	// Minimal valid config.
	f.Add([]byte(`
hss:
  OriginHost: hss.test.net
  OriginRealm: test.net
database:
  db_type: sqlite
`))

	// Deliberately malformed configs.
	f.Add([]byte(`not yaml at all: [[[`))
	f.Add([]byte{})
	f.Add([]byte("hss:\n  OriginHost: \"\"\n"))
	f.Add([]byte("hss:\n  OriginHost: x\n  DiameterDSCP: 99\n"))
	f.Add([]byte("hss:\n  OriginHost: x\n  OriginRealm: x\ndatabase:\n  db_type: postgres\n"))

	// Large garbage.
	f.Add(make([]byte, 8192))

	f.Fuzz(func(t *testing.T, b []byte) {
		// Must not panic; errors are expected for invalid input.
		_, _ = LoadFromBytes(b)
	})
}
