package verifier

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"hash"

	"github.com/ccldd/httpsig"
	"golang.org/x/crypto/sha3"
)

type VerifyingAlgorithm interface {
	httpsig.Algorithm
	Verify(hash []byte, signature []byte) bool
}

type EcdsaVerifyingAlgorithm struct {
	pubKey *ecdsa.PublicKey
	hash   hash.Hash
}

func (alg EcdsaVerifyingAlgorithm) Verify(hash []byte, signature []byte) bool {
	return ecdsa.VerifyASN1(alg.pubKey, hash, signature)
}

type EcdsaP256Sha256VerifyingAlgorithm struct {
	EcdsaVerifyingAlgorithm
}

func NewEcdsaSha256VerifyingAlgorithm(key *ecdsa.PublicKey) EcdsaP256Sha256VerifyingAlgorithm {
	return EcdsaP256Sha256VerifyingAlgorithm{
		EcdsaVerifyingAlgorithm: EcdsaVerifyingAlgorithm{
			pubKey: key,
			hash:   sha256.New(),
		},
	}
}

func (alg EcdsaP256Sha256VerifyingAlgorithm) Name() string {
	return "ecdsa-p256-sha256"
}

type EcdsaP384Sha384VerifyingAlgorithm struct {
	EcdsaVerifyingAlgorithm
}

func NewEcdsaSha384VerifyingAlgorithm(key *ecdsa.PublicKey) EcdsaP384Sha384VerifyingAlgorithm {
	return EcdsaP384Sha384VerifyingAlgorithm{
		EcdsaVerifyingAlgorithm: EcdsaVerifyingAlgorithm{
			pubKey: key,
			hash:   sha3.New384(),
		},
	}
}

func (alg EcdsaP384Sha384VerifyingAlgorithm) Name() string {
	return "ecdsa-p384-sha384"
}
