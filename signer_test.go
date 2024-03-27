package httpsig

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	ECCP256TestKeyId = "test-key-ecc-p256"
)

var ECCP256TestKey *ecdsa.PrivateKey

func init() {
	var err error

	bytes, err := base64.StdEncoding.DecodeString("MHcCAQEEIFKbhfNZfpDsW43+0+JjUr9K+bTeuxopu653+hBaXGA7oAoGCCqGSM49AwEHoUQDQgAEqIVYZVLCrPZHGHjP17CTW0/+D9Lfw0EkjqF7xB4FivAxzic30tMM4GF+hR6Dxh71Z50VGGdldkkDXZCnTNnoXQ==")
	if err != nil {
		panic(err)
	}

	ECCP256TestKey, err = x509.ParseECPrivateKey(bytes)
	if err != nil {
		panic(err)
	}
}

func TestHttpMessageSigner_SignRequest(t *testing.T) {
	opts := &SignOptions{}
	opts.WithCreated()
	opts.WithKeyId(ECCP256TestKeyId)
	signer := NewEcdsaSha256Signer(ECCP256TestKey, "sig1", opts)

	req, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
	if err != nil {
		panic(err)
	}
	signer.SignRequest(req)

	assert.NotEmpty(t, req.Header.Get(HeaderSignature))
}
