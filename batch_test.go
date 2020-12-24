package ed25519consensus

import (
	"crypto/ed25519"
	"fmt"
	"testing"
)

func TestBatch(t *testing.T) {
	v := NewVerifier()
	for i := 0; i <= 38; i++ {

		pub, priv, _ := ed25519.GenerateKey(nil)

		msg := []byte("BatchVerifyTest")

		sig := ed25519.Sign(priv, msg)

		if !v.Add(pub, sig, msg) {
			t.Error("unable to add s k m")
		}
	}

	if !v.VerifyBatch() {
		t.Error("failed batch verification")
	}
}

func BenchmarkVerifyBatch(b *testing.B) {
	for _, n := range []int{1, 8, 64, 1024} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			b.ReportAllocs()
			v := NewVerifier()
			for i := 0; i < n; i++ {
				pub, priv, _ := ed25519.GenerateKey(nil)
				msg := []byte("BatchVerifyTest")
				v.Add(pub, msg, ed25519.Sign(priv, msg))
			}
			// NOTE: dividing by n so that metrics are per-signature
			for i := 0; i < b.N/n; i++ {
				if !v.VerifyBatch() {
					b.Fatal("signature set failed batch verification")
				}
			}
		})
	}
}
