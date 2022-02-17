package dione_crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"github.com/Dione-Software/dione-cryptography/go/key_exchange_proto"
	"golang.org/x/crypto/curve25519"
)

var (
	WrongCurveType             = errors.New("wrong curve type")
	ErrorUnmarshalCurve        = errors.New("error during unmarshal")
	PublicKeyVerificationError = errors.New("error during verification of public key")
	PublicKeyLengthError       = errors.New("public key has the wrong length")
)

const (
	P256 = iota
	Curve25519
)

type ExportablePublicKey interface {
	ExportPublicKey() *key_exchange_proto.PublicKey
	ImportPublicKey(proto *key_exchange_proto.PublicKey) error
}

type P256DhKeypair struct {
	curve      elliptic.Curve
	privateKey *ecdsa.PrivateKey
	publicKey  *ecdsa.PublicKey
}

func NewP256DhKeypair() (*P256DhKeypair, error) {
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	pub := ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     private.X,
		Y:     private.Y,
	}
	ret := &P256DhKeypair{
		curve:      elliptic.P256(),
		privateKey: private,
		publicKey:  &pub,
	}
	return ret, nil
}

func (p *P256DhKeypair) ComputeSharedSecret(publicKey *ecdsa.PublicKey) []byte {
	remoteCurve := publicKey.Curve
	if remoteCurve != p.curve {
		panic("Two different curves used")
	}
	shared, _ := remoteCurve.ScalarMult(publicKey.X, publicKey.Y, p.privateKey.D.Bytes())
	sharedBytes := sha256.Sum256(shared.Bytes())
	ret := make([]byte, 32)
	ret = append(ret, sharedBytes[:]...)
	return ret
}

func (p *P256DhKeypair) GetPublicKey() *ecdsa.PublicKey {
	return p.publicKey
}

func (p *P256DhKeypair) Type() int {
	return P256
}

func (p *P256DhKeypair) ExportPublicKey() *key_exchange_proto.PublicKey {
	ret := new(key_exchange_proto.PublicKey)
	ret.CurveType = key_exchange_proto.PublicKey_P256
	ret.PublicKeyData = elliptic.MarshalCompressed(elliptic.P256(), p.publicKey.X, p.publicKey.Y)
	return ret
}

func (p *P256DhKeypair) ImportPublicKey(proto *key_exchange_proto.PublicKey) error {
	if proto.CurveType != key_exchange_proto.PublicKey_P256 || p.curve != elliptic.P256() {
		return WrongCurveType
	}
	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), proto.PublicKeyData)
	if x == nil || y == nil {
		return ErrorUnmarshalCurve
	}
	pk := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}
	p.publicKey = pk
	return nil
}

type Curve25519DhKeypair struct {
	curve      int
	privateKey [32]byte
	publicKey  [32]byte
}

func NewCurve25519DhKeypair() (*Curve25519DhKeypair, error) {
	var publicKey [32]byte
	var privateKey [32]byte
	_, err := rand.Read(privateKey[:])
	if err != nil {
		return nil, err
	}
	curve25519.ScalarBaseMult(&publicKey, &privateKey)
	if validatePublicKey(publicKey[:]) {
		return &Curve25519DhKeypair{Curve25519, privateKey, publicKey}, nil
	}
	return NewCurve25519DhKeypair()
}

func (c *Curve25519DhKeypair) ComputeSharedSecret(publicKey [32]byte) ([]byte, error) {
	ss, err := curve25519.X25519(c.privateKey[:], publicKey[:])
	return ss, err
}

func (c *Curve25519DhKeypair) GetPublicKey() [32]byte {
	return c.publicKey
}

func (c *Curve25519DhKeypair) ExportPublicKey() *key_exchange_proto.PublicKey {
	return &key_exchange_proto.PublicKey{
		CurveType:     key_exchange_proto.PublicKey_Curve25519,
		PublicKeyData: c.publicKey[:],
	}
}

func (c *Curve25519DhKeypair) ImportPublicKey(proto *key_exchange_proto.PublicKey) error {
	if c.curve != Curve25519 || proto.CurveType != key_exchange_proto.PublicKey_Curve25519 {
		return WrongCurveType
	}
	publicKey := proto.PublicKeyData
	if len(publicKey) != len(c.publicKey) {
		return PublicKeyLengthError
	}
	if !validatePublicKey(publicKey) {
		return PublicKeyVerificationError
	}
	for i := 0; i < 32; i++ {
		c.publicKey[i] = publicKey[i]
	}
	return nil
}

/// validatePublicKey originates from the secure implementation of Noise Explorer (C).
func validatePublicKey(k []byte) bool {
	forbiddenCurveValues := [12][]byte{
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		{224, 235, 122, 124, 59, 65, 184, 174, 22, 86, 227, 250, 241, 159, 196, 106, 218, 9, 141, 235, 156, 50, 177, 253, 134, 98, 5, 22, 95, 73, 184, 0},
		{95, 156, 149, 188, 163, 80, 140, 36, 177, 208, 177, 85, 156, 131, 239, 91, 4, 68, 92, 196, 88, 28, 142, 134, 216, 34, 78, 221, 208, 159, 17, 87},
		{236, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127},
		{237, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127},
		{238, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127},
		{205, 235, 122, 124, 59, 65, 184, 174, 22, 86, 227, 250, 241, 159, 196, 106, 218, 9, 141, 235, 156, 50, 177, 253, 134, 98, 5, 22, 95, 73, 184, 128},
		{76, 156, 149, 188, 163, 80, 140, 36, 177, 208, 177, 85, 156, 131, 239, 91, 4, 68, 92, 196, 88, 28, 142, 134, 216, 34, 78, 221, 208, 159, 17, 215},
		{217, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255},
		{218, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255},
		{219, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 25},
	}

	for _, testValue := range forbiddenCurveValues {
		if subtle.ConstantTimeCompare(k[:], testValue[:]) == 1 {
			return false
		}
	}
	return true
}
