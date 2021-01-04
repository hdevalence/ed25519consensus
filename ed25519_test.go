package ed25519consensus_test

import (
	"crypto/ed25519"
	"testing"

	"github.com/hdevalence/ed25519consensus"
)

func TestSignVerify(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(nil)

	message := []byte("test message")
	sig := ed25519consensus.Sign(private, message)

	if !ed25519consensus.Verify(public, message, sig) {
		t.Errorf("valid signature rejected")
	}

	wrongMessage := []byte("wrong message")
	if ed25519consensus.Verify(public, wrongMessage, sig) {
		t.Errorf("signature of different message accepted")
	}

}
