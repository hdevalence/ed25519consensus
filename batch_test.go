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

	if !v.Verify() {
		t.Error("failed batch verification")
	}
}

func TestBatchFailsOnShortSig(t *testing.T) {
	v := NewBatchVerifier()
	pub, _, _ := ed25519.GenerateKey(nil)
	v.Add(pub, []byte("message"), []byte{})
	if v.Verify() {
		t.Error("batch verification should fail due to short signature")
	}
}

func TestBatchFailsOnCorruptKey(t *testing.T) {
	v := NewBatchVerifier()
	populateBatchVerifier(t, &v)
	v.entries[1].pubkey[1] ^= 1
	if v.Verify() {
		t.Error("batch verification should fail due to corrupt key")
	}
}

func TestBatchFailsOnCorruptSignature(t *testing.T) {
	v := NewBatchVerifier()

	populateBatchVerifier(t, &v)
	// corrupt the R value of one of the signatures
	v.entries[4].signature[1] ^= 1
	if v.Verify() {
		t.Error("batch verification should fail due to corrupt signature")
	}

	populateBatchVerifier(t, &v)
	// negate a scalar to check batch verification fails
	v.entries[1].k.Negate(edwards25519.NewScalar())
	if v.Verify() {
		t.Error("batch verification should fail due to corrupt signature")
	}
}

func TestEmptyBatchFails(t *testing.T) {
	v := NewBatchVerifier()

	if v.Verify() {
		t.Error("batch verification should fail on an empty batch")
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
				if !v.Verify() {
					b.Fatal("signature set failed batch verification")
				}
			}
		})
	}
}

func BenchmarkCreateBatch(b *testing.B) {
	for _, n := range []int{1, 8, 64, 1024, 4096, 16384} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			b.StopTimer()
			msg := []byte("CreateBatch")
			pubs := make([][]byte, n)
			sigs := make([][]byte, n)
			for i := 0; i < n; i++ {
				pub, priv, _ := ed25519.GenerateKey(nil)
				pubs[i] = pub
				sigs[i] = ed25519.Sign(priv, msg)
			}
			b.StartTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				v := NewBatchVerifier()
				for j := 0; j < n; j++ {
					v.Add(pubs[j], msg, sigs[j])
				}
			}
		})
	}
}

func BenchmarkCreatePreallocatedBatch(b *testing.B) {
	for _, n := range []int{1, 8, 64, 1024, 4096, 16384} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			b.StopTimer()
			msg := []byte("CreatePreallocatedBatch")
			pubs := make([][]byte, n)
			sigs := make([][]byte, n)
			for i := 0; i < n; i++ {
				pub, priv, _ := ed25519.GenerateKey(nil)
				pubs[i] = pub
				sigs[i] = ed25519.Sign(priv, msg)
			}
			b.StartTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				v := NewPreallocatedBatchVerifier(n)
				for j := 0; j < n; j++ {
					v.Add(pubs[j], msg, sigs[j])
				}
			}
		})
	}
}

// populateBatchVerifier populates a verifier with multiple entries
func populateBatchVerifier(t *testing.T, v *BatchVerifier) {
	*v = NewBatchVerifier()
	for i := 0; i <= 38; i++ {

		pub, priv, _ := ed25519.GenerateKey(nil)

		var msg []byte
		if i%2 == 0 {
			msg = []byte("easter")
		} else {
			msg = []byte("egg")
		}

		sig := ed25519.Sign(priv, msg)

		v.Add(pub, msg, sig)
	}
}
