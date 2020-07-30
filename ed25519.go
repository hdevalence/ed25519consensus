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

	"github.com/hdevalence/ed25519consensus/internal/edwards25519"
)

// Verify reports whether sig is a valid signature of message by
// publicKey, using precisely-specified validation criteria (ZIP 215) suitable
// for use in consensus-critical contexts.
//
// It will panic if len(publicKey) is not ed25519.PublicKeySize.
func Verify(publicKey ed25519.PublicKey, message, sig []byte) bool {
	if l := len(publicKey); l != ed25519.PublicKeySize {
		panic("ed25519: bad public key length: " + strconv.Itoa(l))
	}

	if len(sig) != ed25519.SignatureSize || sig[63]&224 != 0 {
		return false
	}

	var A edwards25519.ExtendedGroupElement
	var publicKeyBytes [32]byte
	copy(publicKeyBytes[:], publicKey)
	// ZIP215: this works because FromBytes does not check that encodings are canonical.
	if !A.FromBytes(&publicKeyBytes) {
		return false
	}
	edwards25519.FeNeg(&A.X, &A.X)
	edwards25519.FeNeg(&A.T, &A.T)

	h := sha512.New()
	h.Write(sig[:32])
	h.Write(publicKey[:])
	h.Write(message)
	var digest [64]byte
	h.Sum(digest[:0])

	var hReduced [32]byte
	edwards25519.ScReduce(&hReduced, &digest)

	var r [32]byte
	copy(r[:], sig[:32])
	var checkR edwards25519.ExtendedGroupElement
	// ZIP215: this works because FromBytes does not check that encodings are canonical.
	if !checkR.FromBytes(&r) {
		return false
	}

	var s [32]byte
	copy(s[:], sig[32:])

	// https://tools.ietf.org/html/rfc8032#section-5.1.7 requires that s be in
	// the range [0, order) in order to prevent signature malleability.
	// ZIP215: This is also required by ZIP215.
	if !edwards25519.ScMinimal(&s) {
		return false
	}

	var Rproj edwards25519.ProjectiveGroupElement
	var R edwards25519.ExtendedGroupElement
	edwards25519.GeDoubleScalarMultVartime(&Rproj, &hReduced, &A, &s)
	Rproj.ToExtended(&R)

	// ZIP215: We want to check [8](R - R') == 0
	return edwards25519.CofactorEqual(&R, &checkR)
}
