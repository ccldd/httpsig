package signer

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/ccldd/httpsig"
)

var (
	ErrNoSigLabel    = errors.New("missing sigLabel")
	ErrNothingToSign = errors.New("there are nothing to sign in the http message")
)

type Signer interface {
	SignRequest(req *http.Request) error
}

// HttpMessageSigner implements Signer
// using SigningAlgorithm
type HttpMessageSigner struct {
	components          []string
	signatureParameters []httpsig.SignatureParameter

	alg      SigningAlgorithm
	sigLabel string
}

func (hms HttpMessageSigner) validate() error {
	errs := make([]error, 0)

	if hms.sigLabel == "" {
		errs = append(errs, ErrNoSigLabel)
	}

	return errors.Join(errs...)
}

func new(opts ...Option) *HttpMessageSigner {
	signer := &HttpMessageSigner{}
	for _, opt := range opts {
		opt(signer)
	}

	return signer
}

func New(alg SigningAlgorithm, sigLabel string, opts ...Option) (*HttpMessageSigner, error) {
	s := new(opts...)
	s.alg = alg
	s.sigLabel = sigLabel

	if err := s.validate(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *HttpMessageSigner) SignRequest(req *http.Request) error {
	msg := &httpsig.HttpRequest{Request: req}
	errors.Join()

	// Form Signature Base
	sb, err := httpsig.NewSignatureBaseFromRequest(msg, s.components, s.signatureParameters)
	if err != nil {
		return fmt.Errorf("HttpMessageSigner.SignRequest error creating signature base: %w", err)
	}

	sbString, err := sb.Marshal()
	if err != nil {
		return fmt.Errorf("HttpMessageSigner.SignRequest error marshalling signature base: %w", err)
	}

	// Calculate Signature
	sbBytes := []byte(sbString)
	signatureBytes, err := s.alg.Sign(sbBytes)
	if err != nil {
		return fmt.Errorf("HttpMessageSigner.SignRequest error generating signature: %w", err)
	}

	// Add signature to headers
	signatureHeaderValue, err := httpsig.SignatureHeaderValue(s.sigLabel, signatureBytes)
	if err != nil {
		return fmt.Errorf("HttpMessageSigner.SignRequest error adding %s: %w", strconv.Quote(httpsig.HeaderSignature), err)
	}
	msg.Header().Add(httpsig.HeaderSignature, signatureHeaderValue)

	// Add Signature-Input to headers
	signatureInput := httpsig.SignatureInputFromSignatureParams(s.sigLabel, &sb.SignatureParams)
	signatureInputStr, err := signatureInput.Marshal()
	if err != nil {
		return fmt.Errorf("HttpMessageSigner.SignRequest error adding %s: %w", strconv.Quote(httpsig.HeaderSignatureInput), err)
	}

	msg.Header().Add(httpsig.HeaderSignatureInput, signatureInputStr)

	return nil
}
