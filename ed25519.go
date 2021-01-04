// Copyright 2016 The Go Authors. All rights reserved.
// Copyright 2016 Henry de Valence. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package ed25519consensus implements Ed25519 verification according to ZIP215.
package ed25519consensus

import (
	"crypto/ed25519"
	"crypto/sha512"
	"strconv"

	"filippo.io/edwards25519"
)

// Verify reports whether sig is a valid signature of message by
// publicKey, using precisely-specified validation criteria (ZIP 215) suitable
// for use in consensus-critical contexts.
func Verify(publicKey ed25519.PublicKey, message, sig []byte) bool {
	if l := len(publicKey); l != ed25519.PublicKeySize {
		return false
	}

	if len(sig) != ed25519.SignatureSize || sig[63]&224 != 0 {
		return false
	}

	// ZIP215: this works because SetBytes does not check that encodings are canonical.
	A, err := new(edwards25519.Point).SetBytes(publicKey)
	if err != nil {
		return false
	}
	A.Negate(A)

	h := sha512.New()
	h.Write(sig[:32])
	h.Write(publicKey[:])
	h.Write(message)
	var digest [64]byte
	h.Sum(digest[:0])

	hReduced := new(edwards25519.Scalar).SetUniformBytes(digest[:])

	// ZIP215: this works because SetBytes does not check that encodings are canonical.
	checkR, err := new(edwards25519.Point).SetBytes(sig[:32])
	if err != nil {
		return false
	}

	// https://tools.ietf.org/html/rfc8032#section-5.1.7 requires that s be in
	// the range [0, order) in order to prevent signature malleability.
	// ZIP215: This is also required by ZIP215.
	s, err := new(edwards25519.Scalar).SetCanonicalBytes(sig[32:])
	if err != nil {
		return false
	}

	R := new(edwards25519.Point).VarTimeDoubleScalarBaseMult(hReduced, A, s)

	// ZIP215: We want to check [8](R - checkR) == 0
	p := new(edwards25519.Point).Subtract(R, checkR) // p = R - checkR
	p.MultByCofactor(p)
	return p.Equal(edwards25519.NewIdentityPoint()) == 1 // p == 0
}

// Sign signs the message with privateKey and returns a signature. It will
// panic if len(privateKey) is not PrivateKeySize.
//todo: Once https://go-review.googlesource.com/c/go/+/276272 is accepted and released replace with standard lib ed25519
func Sign(privateKey ed25519.PrivateKey, message []byte) []byte {
	// Outline the function body so that the returned signature can be
	// stack-allocated.
	signature := make([]byte, ed25519.SignatureSize)
	sign(signature, privateKey, message)
	return signature
}

func sign(signature, privateKey, message []byte) {
	if l := len(privateKey); l != ed25519.PrivateKeySize {
		panic("ed25519: bad private key length: " + strconv.Itoa(l))
	}

	seed, publicKey := privateKey[:ed25519.SeedSize], privateKey[ed25519.SeedSize:]
	h := sha512.Sum512(seed)
	s := edwards25519.NewScalar().SetBytesWithClamping(h[:32])
	prefix := h[32:]

	mh := sha512.New()
	mh.Write(prefix)
	mh.Write(message)

	messageDigest := make([]byte, 0, sha512.Size)
	messageDigest = mh.Sum(messageDigest)

	r := edwards25519.NewScalar().SetUniformBytes(messageDigest)
	R := (&edwards25519.Point{}).ScalarBaseMult(r)

	kh := sha512.New()
	kh.Write(R.Bytes())
	kh.Write(publicKey)
	kh.Write(message)

	hramDigest := make([]byte, 0, sha512.Size)
	hramDigest = kh.Sum(hramDigest)

	k := edwards25519.NewScalar().SetUniformBytes(hramDigest)
	S := edwards25519.NewScalar().MultiplyAdd(k, s, r)

	copy(signature[:32], R.Bytes())
	copy(signature[32:], S.Bytes())
}
