package signer_test

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/ccldd/httpsig"
	"github.com/ccldd/httpsig/signer"
	"github.com/stretchr/testify/assert"
)

const (
	ECCP256TestKeyId = "test-key-ecc-p256"
)

var ECCP256TestKey *ecdsa.PrivateKey

func TestMain(m *testing.M) {
	var err error

	bytes, err := base64.StdEncoding.DecodeString("MHcCAQEEIFKbhfNZfpDsW43+0+JjUr9K+bTeuxopu653+hBaXGA7oAoGCCqGSM49AwEHoUQDQgAEqIVYZVLCrPZHGHjP17CTW0/+D9Lfw0EkjqF7xB4FivAxzic30tMM4GF+hR6Dxh71Z50VGGdldkkDXZCnTNnoXQ==")
	if err != nil {
		panic(err)
	}

	ECCP256TestKey, err = x509.ParseECPrivateKey(bytes)
	if err != nil {
		panic(err)
	}

	m.Run()
}

func TestHttpMessageSigner_SignRequest(t *testing.T) {
	assert := assert.New(t)

	alg, err := signer.NewEcdsaSha256(ECCP256TestKey)
	assert.NoError(err)

	signer, err := signer.New(alg, "sig1", signer.WithCreated(), signer.WithKeyId(ECCP256TestKeyId))
	assert.NoError(err)

	req, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
	assert.NoError(err)
	signer.SignRequest(req)

	assert.NotEmpty(req.Header.Get(httpsig.HeaderSignature))
}
