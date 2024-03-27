package httpsig

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"
	"net/http"
	"strconv"
)

var (
	ErrNothingToSign = errors.New("there are nothing to sign in the http message")
	ErrWrongCurve    = errors.New("the private key belongs in the wrong curve")
)

type Signer interface {
	SignRequest(req *http.Request) error
}

// HttpMessageSigner implements Signer
// using SigningAlgorithm
type HttpMessageSigner struct {
	Alg      SigningAlgorithm
	SigLabel string
	Opts     *SignOptions
}

func NewEcdsaP256Sha256Signer(privateKey *ecdsa.PrivateKey, sigLabel string, opts *SignOptions) (*HttpMessageSigner, error) {
	if privateKey.Curve != elliptic.P256() {
		return nil, ErrWrongCurve
	}

	return &HttpMessageSigner{
		Alg: EcdsaP256Sha256Algorithm{
			privateKey: privateKey,
		},
		SigLabel: sigLabel,
		Opts:     opts,
	}, nil
}

func NewEcdsaP384Sha384Signer(privateKey *ecdsa.PrivateKey, sigLabel string, opts *SignOptions) (*HttpMessageSigner, error) {
	if privateKey.Curve != elliptic.P384() {
		return nil, ErrWrongCurve
	}

	return &HttpMessageSigner{
		Alg: EcdsaP384Sha384Algorithm{
			privateKey: privateKey,
		},
		SigLabel: sigLabel,
		Opts:     opts,
	}, nil
}

func (s *HttpMessageSigner) SignRequest(req *http.Request) error {
	msg := &HttpRequest{req}

	// Form Signature Base
	sb, err := NewSignatureBaseFromRequest(msg, s.Opts.components, s.Opts.signatureParameters)
	if err != nil {
		return fmt.Errorf("HttpMessageSigner.SignRequest error creating signature base: %w", err)
	}

	sbString, err := sb.Marshal()
	if err != nil {
		return fmt.Errorf("HttpMessageSigner.SignRequest error marshalling signature base: %w", err)
	}

	// Calculate Signature
	sbBytes := []byte(sbString)
	signatureBytes, err := s.Alg.Sign(sbBytes)
	if err != nil {
		return fmt.Errorf("HttpMessageSigner.SignRequest error generating signature: %w", err)
	}

	// Add signature to headers
	signatureHeaderValue, err := SignatureHeaderValue(s.SigLabel, signatureBytes)
	if err != nil {
		return fmt.Errorf("HttpMessageSigner.SignRequest error adding %s: %w", strconv.Quote(HeaderSignature), err)
	}
	msg.Header().Add(HeaderSignature, signatureHeaderValue)

	// Add Signature-Input to headers
	signatureInput := SignatureInputFromSignatureParams(s.SigLabel, &sb.SignatureParams)
	signatureInputStr, err := signatureInput.Marshal()
	if err != nil {
		return fmt.Errorf("HttpMessageSigner.SignRequest error adding %s: %w", strconv.Quote(HeaderSignatureInput), err)
	}

	msg.Header().Add(HeaderSignatureInput, signatureInputStr)

	return nil
}
