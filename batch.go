package ed25519consensus

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"

	"filippo.io/edwards25519"
)

// BatchVerifier holds entries of public keys, signature and a scalar which are used for batch verification.
type BatchVerifier struct {
	entries []ks
}

// ks represents the public key, signature and scalar which the caller wants to batch verify
type ks struct {
	pubkey    ed25519.PublicKey
	signature []byte
	k         *edwards25519.Scalar
}

// NewBatchVerifier creates a Verifier that entries of signatures, keys and messages
// can be added to for verification
func NewBatchVerifier() BatchVerifier {
	return BatchVerifier{
		entries: []ks{},
	}
}

// Add adds a (public key, signature, message) triple to the current batch.
func (v *BatchVerifier) Add(publicKey ed25519.PublicKey, sig, message []byte) bool {
	if l := len(publicKey); l != ed25519.PublicKeySize {
		return false
	}

	if len(sig) != ed25519.SignatureSize || sig[63]&224 != 0 {
		return false
	}

	h := sha512.New()
	h.Write(sig[:32])
	h.Write(publicKey)
	h.Write(message)
	var digest [64]byte
	h.Sum(digest[:0])

	k := new(edwards25519.Scalar).SetUniformBytes(digest[:])

	ksS := ks{
		pubkey:    publicKey,
		signature: sig,
		k:         k,
	}

	v.entries = append(v.entries, ksS)

	return true
}

// Verify checks all entries in the current batch, returning `true` if
// *all* entries are valid and `false` if *any one* entry is invalid.
//
// If a failure arises it is unknown which entry failed, the caller must verify each entry individually.
func (v *BatchVerifier) VerifyBatch() bool {
	// The batch verification equation is
	//
	// [-sum(z_i * s_i)]B + sum([z_i]R_i) + sum([z_i * k_i]A_i) = 0.
	// where for each signature i,
	// - A_i is the verification key;
	// - R_i is the signature's R value;
	// - s_i is the signature's s value;
	// - k_i is the hash of the message and other data;
	// - z_i is a random 128-bit Scalar.
	vl := len(v.entries)
	svals := make([]edwards25519.Scalar, 1+vl+vl)
	scalars := make([]*edwards25519.Scalar, 1+vl+vl)

	// Populate scalars variable with concrete scalars to reduce heap allocation
	for i := range scalars {
		scalars[i] = &svals[i]
	}

	Bcoeff := scalars[0]
	Rcoeffs := scalars[1:][:int(vl)]
	Acoeffs := scalars[1+vl:]

	pvals := make([]edwards25519.Point, 1+vl+vl)
	points := make([]*edwards25519.Point, 1+vl+vl)
	for i := range points {
		points[i] = &pvals[i]
	}
	B := points[0]
	Rs := points[1:][:vl]
	As := points[1+vl:]

	B.Set(edwards25519.NewGeneratorPoint())
	for i, entry := range v.entries {
		if _, err := Rs[i].SetBytes(entry.signature[:32]); err != nil {
			return false
		}

		if _, err := As[i].SetBytes(entry.pubkey); err != nil {
			return false
		}

		buf := make([]byte, 32)
		rand.Read(buf[:16])
		_, err := Rcoeffs[i].SetCanonicalBytes(buf)
		if err != nil {
			return false
		}

		s, err := new(edwards25519.Scalar).SetCanonicalBytes(entry.signature[32:])
		if err != nil {
			return false
		}
		Bcoeff.MultiplyAdd(Rcoeffs[i], s, Bcoeff)

		Acoeffs[i].Multiply(Rcoeffs[i], entry.k)
	}
	Bcoeff.Negate(Bcoeff) // this term is subtracted in the summation

	// purge BatchVerifier for reuse
	v.entries = []ks{}

	check := new(edwards25519.Point).VarTimeMultiScalarMult(scalars, points)
	check.MultByCofactor(check)
	return check.Equal(edwards25519.NewIdentityPoint()) == 1
}
