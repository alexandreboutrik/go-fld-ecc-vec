package eddsa_avx2

import (
	"bytes"
	"testing"
)

func Test_Key_Generation(t *testing.T) {
	pub, priv, err := Keygen()
	if err != nil {
		t.Fatalf("Keygen() failed: %v", err)
	}

	if pub == nil || priv == nil {
		t.Fatalf("Keygen() returned a nil key")
	}

	if len(pub.Bytes()) != ED25519_KEY_SIZE_BYTES_PARAM || len(priv.Bytes()) != ED25519_KEY_SIZE_BYTES_PARAM {
		t.Fatalf("keys have incorrect length: got %d|%d, expected %d", len(pub.Bytes()), len(priv.Bytes()), ED25519_KEY_SIZE_BYTES_PARAM)
	}
}

func Test_Valid_Signature(t *testing.T) {
	pub, priv, err := Keygen()
	if err != nil {
		t.Fatalf("Keygen() failed: %v", err)
	}

	message := []byte("this is a test message")

	signature, err := priv.Sign(nil, message, nil)
	if err != nil {
		t.Fatalf("Sign() failed: %v", err)
	}

	if len(signature) != ED25519_SIG_SIZE_BYTES_PARAM {
		t.Fatalf("Sign() returned signature of incorrect length: got %d, expected %d", len(signature), ED25519_SIG_SIZE_BYTES_PARAM)
	}

	valid := pub.Verify(message, signature)
	if !valid {
		t.Fatalf("Verify() failed for a valid signature: %v", err)
	}
}

func Test_Invalid_Signature(t *testing.T) {
	pub, priv, err := Keygen()
	if err != nil {
		t.Fatalf("Keygen() failed: %v", err)
	}

	message := []byte("this is a test message")

	signature, err := priv.Sign(nil, message, nil)
	if err != nil {
		t.Fatalf("Sign() failed: %v", err)
	}

	if len(signature) > 0 {
		signature[0] ^= 0xff // tamper with the signature, flip the first byte
	} else {
		t.Fatalf("Sign() returned an empty signature")
	}

	valid := pub.Verify(message, signature)
	if valid {
		t.Fatalf("Verify() succeeded for an invalid signature, but it should have failed")
	}
}

func Test_Key_Serialization(t *testing.T) {
	pubOrig, privOrig, err := Keygen()
	if err != nil {
		t.Fatalf("Keygen() failed: %v", err)
	}

	pubBytes := pubOrig.Bytes()
	privBytes := privOrig.Bytes()

	pubNew, err := PublicKeyFromBytes(pubBytes)
	if err != nil {
		t.Fatalf("PublicKeyFromBytes() failed: %v", err)
	}

	privNew, err := PrivateKeyFromBytes(privBytes)
	if err != nil {
		t.Fatalf("PrivateKeyFromBytes() failed: %v", err)
	}

	if !bytes.Equal(pubOrig.Bytes(), pubNew.Bytes()) {
		t.Fatalf("deserialized public key does not match the original")
	}

	if !bytes.Equal(privOrig.Bytes(), privNew.Bytes()) {
		t.Fatalf("deserialized private key does not match the original")
	}
}

func Test_PrivateKeyFromBytes_PublicKey_Reconstruction(t *testing.T) {
	pub, priv, err := Keygen()
	if err != nil {
		t.Fatalf("Keygen() failed: %v", err)
	}

	privBytes := priv.Bytes()

	priv2, err := PrivateKeyFromBytes(privBytes)
	if err != nil {
		t.Fatalf("PrivateKeyFromBytes() failed: %v", err)
	}

	if !bytes.Equal(pub.Bytes(), priv2.Public().(*PublicKey).Bytes()) {
		t.Fatalf("reconstructed public key does not match the original public key")
	}
}

func Test_Verify_With_Wrong_Digest(t *testing.T) {
	pub, priv, err := Keygen()
	if err != nil {
		t.Fatalf("Keygen() failed: %v", err)
	}

	originalMessage := []byte("this is a test message")
	wrongDigest := []byte("this is a different message")

	signature, err := priv.Sign(nil, originalMessage, nil)
	if err != nil {
		t.Fatalf("Sign() failed: %v", err)
	}	
	if len(signature) != ED25519_SIG_SIZE_BYTES_PARAM {
		t.Fatalf("Sign() returned signature of incorrect length: got %d, expected %d", len(signature), ED25519_SIG_SIZE_BYTES_PARAM)
	}

	valid := pub.Verify(wrongDigest, signature)
	if valid {
		t.Fatalf("Verify() succeeded for a valid signature but wrong digest")
	}
}
