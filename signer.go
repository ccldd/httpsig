package httpsig

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"net/http"
	"strconv"
)

var (
	ErrNothingToSign = errors.New("there are nothing to sign in the http message")
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

func NewEcdsaSha256Signer(privateKey *ecdsa.PrivateKey, sigLabel string, opts *SignOptions) *HttpMessageSigner {
	return &HttpMessageSigner{
		Alg: EcdsaSha256Algorithm{
			privateKey: privateKey,
		},
		SigLabel: sigLabel,
		Opts:     opts,
	}
}

func NewEcdsaSha384Signer(privateKey *ecdsa.PrivateKey, sigLabel string, opts *SignOptions) *HttpMessageSigner {
	return &HttpMessageSigner{
		Alg: EcdsaSha384Algorithm{
			privateKey: privateKey,
		},
		SigLabel: sigLabel,
		Opts:     opts,
	}
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
