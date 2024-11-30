package signer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"hash"

	"github.com/ccldd/httpsig"
	"github.com/ccldd/httpsig/verifier"
	"golang.org/x/crypto/sha3"
)

type SigningAlgorithm interface {
	httpsig.Algorithm
	Sign(b []byte) ([]byte, error)
}

type ecdsaSigningAlgorithm struct {
	verifier.EcdsaVerifyingAlgorithm
	privKey *ecdsa.PrivateKey
	hash    hash.Hash
}

func (alg ecdsaSigningAlgorithm) Sign(b []byte) ([]byte, error) {
	defer alg.hash.Reset()

	_, err := alg.hash.Write(b)
	if err != nil {
		return nil, err
	}

	digest := alg.hash.Sum(nil)
	signed, err := alg.privKey.Sign(rand.Reader, digest[:], nil)
	if err != nil {
		return nil, err
	}

	return signed, nil
}

type EcdsaP256Sha256SigningAlgorithm struct {
	ecdsaSigningAlgorithm
	verifier.EcdsaP256Sha256VerifyingAlgorithm
}

func NewEcdsaSha256(key *ecdsa.PrivateKey) (e EcdsaP256Sha256SigningAlgorithm, err error) {
	if key == nil {
		err = fmt.Errorf("key is nil")
		return
	}
	if key.Curve != elliptic.P256() {
		err = fmt.Errorf("key is not on the P256 curve")
		return
	}

	e.ecdsaSigningAlgorithm = ecdsaSigningAlgorithm{
		privKey: key,
		hash:    sha256.New(),
	}

	return
}

type EcdsaP384Sha384SigningAlgorithm struct {
	ecdsaSigningAlgorithm
	verifier.EcdsaP384Sha384VerifyingAlgorithm
}

func NewEcdsaP384Sha384SigningAlgorithm(key *ecdsa.PrivateKey) (e EcdsaP384Sha384SigningAlgorithm, err error) {
	if key == nil {
		err = fmt.Errorf("key is nil")
		return
	}
	if key.Curve != elliptic.P384() {
		err = fmt.Errorf("key is not on the P384 curve")
		return
	}

	e.ecdsaSigningAlgorithm = ecdsaSigningAlgorithm{
		privKey: key,
		hash:    sha3.New384(),
	}

	return
}
