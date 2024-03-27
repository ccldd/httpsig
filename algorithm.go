package httpsig

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"

	"golang.org/x/crypto/sha3"
)

type Algorithm interface {
	// The algorithm name which is also the value used
	// for the alg signature parameter
	//
	// https://datatracker.ietf.org/doc/html/rfc9421#name-initial-contents
	Name() string
}

type SigningAlgorithm interface {
	Algorithm
	Sign(b []byte) ([]byte, error)
}

type VerifyingAlgorithm interface {
	Algorithm
	Verify(b []byte) error
}

type EcdsaSha256Algorithm struct {
	privateKey *ecdsa.PrivateKey
}

func (alg EcdsaSha256Algorithm) Name() string {
	return "ecdsa-p256-sha256"
}

func (alg EcdsaSha256Algorithm) Sign(b []byte) ([]byte, error) {
	digest := sha256.Sum256(b)
	signed, err := ecdsa.SignASN1(rand.Reader, alg.privateKey, digest[:])
	if err != nil {
		return nil, err
	}

	return signed, nil
}

type EcdsaSha384Algorithm struct {
	privateKey *ecdsa.PrivateKey
}

func (alg EcdsaSha384Algorithm) Name() string {
	return "ecdsa-p384-sha384"
}

func (alg EcdsaSha384Algorithm) Sign(b []byte) ([]byte, error) {
	digest := sha3.Sum384(b)
	signed, err := ecdsa.SignASN1(rand.Reader, alg.privateKey, digest[:])
	if err != nil {
		return nil, err
	}

	return signed, nil
}
