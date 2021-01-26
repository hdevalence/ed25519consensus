package ed25519consensus

import (
	"crypto/ed25519"
	"fmt"
	"testing"

	"filippo.io/edwards25519"
)

func TestBatch(t *testing.T) {
	v := NewBatchVerifier()
	populateBatchVerifier(t, &v)

	if !v.VerifyBatch() {
		t.Error("failed batch verification")
	}

	// corrput a key to check batch verification fails
	populateBatchVerifier(t, &v)
	v.entries[1].pubkey[1] ^= 1
	if v.VerifyBatch() {
		t.Error("batch verification should fail due to corrupt key")
	}

	// corrput a signature to check batch verification fails
	populateBatchVerifier(t, &v)
	v.entries[4].signature[1] ^= 1
	if v.VerifyBatch() {
		t.Error("batch verification should fail due to corrupt key")
	}

	populateBatchVerifier(t, &v)
	// negate a scalar to check batch verification fails
	v.entries[1].k.Negate(edwards25519.NewScalar())
	if v.VerifyBatch() {
		t.Error("batch verification should fail due to corrupt key")
	}

}

func BenchmarkVerifyBatch(b *testing.B) {
	for _, n := range []int{1, 8, 64, 1024} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			b.ReportAllocs()
			v := NewBatchVerifier()
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

// populateBatchVerifier populates a verifier with multiple entries
func populateBatchVerifier(t *testing.T, v *BatchVerifier) {
	for i := 0; i <= 38; i++ {

		pub, priv, _ := ed25519.GenerateKey(nil)

		var msg []byte
		if i%2 == 0 {
			msg = []byte("easter")
		} else {
			msg = []byte("egg")
		}

		sig := ed25519.Sign(priv, msg)

		if !v.Add(pub, sig, msg) {
			t.Error("unable to add s k m")
		}
	}
}
