package dione_crypto

import (
	"bytes"
	"crypto/elliptic"
	"errors"
	"testing"
)

func TestP256DhKeypair_ComputeSharedSecret(t *testing.T) {
	pairA, err := NewP256DhKeypair()
	if err != nil {
		t.Fatalf("Error while creating pair A %v", err)
	}
	pairB, err := NewP256DhKeypair()
	if err != nil {
		t.Fatalf("Error while creating pair B %v", err)
	}
	pubA := pairA.GetPublicKey()
	pubB := pairB.GetPublicKey()
	sharedA := pairA.ComputeSharedSecret(pubB)
	sharedB := pairB.ComputeSharedSecret(pubA)
	if !bytes.Equal(sharedA, sharedB) {
		t.Errorf("Shared secrets are not equal")
	}
}

func TestP256DhKeypair_Proto(t *testing.T) {
	pair, err := NewP256DhKeypair()
	if err != nil {
		t.Fatalf("Error while creating pair %v", err)
	}
	protoKey := pair.ExportPublicKey()
	importKey := &P256DhKeypair{elliptic.P256(), nil, nil}
	err = importKey.ImportPublicKey(protoKey)
	if err != nil {
		t.Fatalf("Error while importing key pair %v", err)
	}
	if !importKey.publicKey.Equal(pair.publicKey) {
		t.Errorf("Public keys are not equal")
	}
	wrongImportKey := &P256DhKeypair{elliptic.P521(), nil, nil}
	err = wrongImportKey.ImportPublicKey(protoKey)
	if !errors.Is(err, WrongCurveType) {
		t.Errorf("Didn't detect issues while importing %v", err)
	}
	// Removing 5 bytes to check weather the system detects missing bytes
	protoKey.PublicKeyData = append(protoKey.PublicKeyData[:10], protoKey.PublicKeyData[15:]...)
	err = importKey.ImportPublicKey(protoKey)
	if !errors.Is(err, ErrorUnmarshalCurve) {
		t.Errorf("Didn't detect this")
	}
}

func TestCurve25519DhKeypair_ComputeSharedSecret(t *testing.T) {
	pairA, err := NewCurve25519DhKeypair()
	if err != nil {
		t.Fatalf("Error while creating pair A %v", err)
	}
	pairB, err := NewCurve25519DhKeypair()
	if err != nil {
		t.Fatalf("Error while creating pair B %v", err)
	}
	pubA := pairA.GetPublicKey()
	pubB := pairB.GetPublicKey()
	sharedA, err := pairA.ComputeSharedSecret(pubB)
	if err != nil {
		t.Fatalf("Error while computing shared secret %v", err)
	}
	sharedB, err := pairB.ComputeSharedSecret(pubA)
	if err != nil {
		t.Fatalf("Error while computing shared secret %v", err)
	}
	if !bytes.Equal(sharedA, sharedB) {
		t.Errorf("Error while deriving shared secret, failed")
	}
}

func TestCurve25519DhKeypair_Proto(t *testing.T) {
	pair, err := NewCurve25519DhKeypair()
	if err != nil {
		t.Fatalf("Error while creating pair %v", err)
	}
	protoKey := pair.ExportPublicKey()
	var prK [32]byte
	var puK [32]byte
	importKey := &Curve25519DhKeypair{Curve25519, prK, puK}
	err = importKey.ImportPublicKey(protoKey)
	if err != nil {
		t.Fatalf("Error while importing key pair %v", err)
	}
	if !bytes.Equal(importKey.publicKey[:], pair.publicKey[:]) {
		t.Errorf("public keys are not equal, as they should be")
	}

	wrongImportKey := &Curve25519DhKeypair{P256, prK, puK}
	err = wrongImportKey.ImportPublicKey(protoKey)
	if !errors.Is(err, WrongCurveType) {
		t.Errorf("Didn't detect issues while importing invalid key")
	}
	// Removing 5 bytes to check weather the system detects missing bytes
	protoKey.PublicKeyData = append(protoKey.PublicKeyData[:10], protoKey.PublicKeyData[15:]...)
	err = importKey.ImportPublicKey(protoKey)
	if !errors.Is(err, PublicKeyLengthError) {
		t.Errorf("Didn't detect this")
	}
	protoKey.PublicKeyData = make([]byte, 32)
	err = importKey.ImportPublicKey(protoKey)
	if !errors.Is(err, PublicKeyVerificationError) {
		t.Errorf("Didn't detect public key verification error")
	}
}
