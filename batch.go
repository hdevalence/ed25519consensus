package ed25519consensus

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"

	"filippo.io/edwards25519"
)

var B = edwards25519.NewGeneratorPoint()

type Verifier struct {
	entries   []ks
	batchSize uint32
}

type ks struct {
	pubkey    ed25519.PublicKey
	signature []byte
	k         *edwards25519.Scalar
}

// NewVerifier creates a Verifier that entries of signatures, keys and messages
// can be added to for verification
func NewVerifier() Verifier {
	return Verifier{
		entries:   []ks{},
		batchSize: 0,
	}
}

// Add adds an entry to the verifier and bumps the batch size.
func (v *Verifier) Add(publicKey ed25519.PublicKey, sig, message []byte) bool {
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
	v.batchSize++

	return true
}

// VerifyBatch batch verifies the keys, messages and signatures within the verifier.
// If a failure arises it is unknown which key failed, the caller must verify each entry individually
func (v *Verifier) VerifyBatch() bool {
	// The batch verification equation is
	//
	// [-sum(z_i * s_i)]B + sum([z_i]R_i) + sum([z_i * k_i]A_i) = 0.
	// where for each signature i,
	// - A_i is the verification key;
	// - R_i is the signature's R value;
	// - s_i is the signature's s value;
	// - k_i is the hash of the message and other data;
	// - z_i is a random 128-bit Scalar.

	svals := make([]edwards25519.Scalar, 1+v.batchSize+v.batchSize)
	scalars := make([]*edwards25519.Scalar, 1+v.batchSize+v.batchSize)
	for i := range scalars {
		scalars[i] = &svals[i]
	}

	Bcoeff := scalars[0]
	Rcoeffs := scalars[1:][:int(v.batchSize)]
	Acoeffs := scalars[1+v.batchSize:]

	pvals := make([]edwards25519.Point, 1+v.batchSize+v.batchSize)
	points := make([]*edwards25519.Point, 1+v.batchSize+v.batchSize)
	for i := range points {
		points[i] = &pvals[i]
	}
	B := points[0]
	Rs := points[1:][:v.batchSize]
	As := points[1+v.batchSize:]

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

	check := new(edwards25519.Point).VarTimeMultiScalarMult(scalars, points)
	check.MultByCofactor(check)
	return check.Equal(edwards25519.NewIdentityPoint()) == 1
}
