package verifier

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/ccldd/httpsig"
)

type Verifier interface {
	VerifyRequest(req *http.Request) (VerifyResult, error)
}

type VerifyResult struct {
	signatureInput httpsig.SignatureInput
}

type HttpMessageVerifier struct {
	alg VerifyingAlgorithm

	sigLabel                   string
	validateFirstSignature     bool
	validateIfOnlyOneSignature bool

	createdTolerance time.Duration
	expiredTolerance time.Duration
}

func (hmv *HttpMessageVerifier) VerifyRequest(req *http.Request) (res VerifyResult, err error) {
	msg := httpsig.HttpRequest{Request: req}

	// Get the signature we want to verify
	var signature httpsig.SignatureHeaderValue
	var sigLabel string
	signature, sigLabel, err = hmv.getSignatureToVerify(msg)
	if err != nil {
		err = fmt.Errorf("error verifying: %w", err)
		return
	}

	var sigInput httpsig.SignatureInput
	sigInput, err = msg.GetSignatureInput(sigLabel)
	if err != nil {
		err = fmt.Errorf("error verifying: %w", err)
		return
	}
	res.signatureInput = sigInput

	// Parse and validate the signature parameters
	sigParamErrs := make([]error, 0)
	sigParams := sigInput.SignatureParameters()
	for _, p := range sigParams {
		switch pp := p.(type) {
		case httpsig.Created:
			pp.Tolerance = hmv.createdTolerance
		case httpsig.Expires:
			pp.Tolerance = hmv.expiredTolerance
		}

		sigParamErrs = append(sigParamErrs, p.Validate())
	}
	if err = errors.Join(sigParamErrs...); err != nil {
		err = fmt.Errorf("error verifying: %w", err)
		return
	}

	// Create the signature base
	components := sigInput.Components()
	sigBase, err := httpsig.NewSignatureBaseFromRequest(msg, components, sigParams)
	if err != nil {
		err = fmt.Errorf("error verifying: %w", err)
		return
	}

	sigBaseStr, err := sigBase.Marshal()
	if err != nil {
		err = fmt.Errorf("error verifying: %w", err)
		return
	}

	sigBaseBytes := []byte(sigBaseStr)
	sigBytes, err := signature.Bytes()
	if err != nil {
		err = fmt.Errorf("error verifying: %w", err)
	}

	if sigValid := hmv.alg.Verify(sigBaseBytes, sigBytes); !sigValid {
		err = fmt.Errorf("error verifying: expected signature does not match actual signature")
	}

	return
}

func (hmv *HttpMessageVerifier) getSignatureToVerify(msg httpsig.SignedHttpMessage) (sig httpsig.SignatureHeaderValue, sigLabel string, err error) {
	sigLabels := msg.SigLabels()

	switch {
	case hmv.validateIfOnlyOneSignature && len(sigLabels) > 1:
		err = fmt.Errorf("multiple signatures found: %v", sigLabels)
	case hmv.validateIfOnlyOneSignature:
	case hmv.validateFirstSignature:
		sigLabel = sigLabels[0]
		sig, err = msg.GetSignature(sigLabel)
	case hmv.sigLabel == "":
		err = fmt.Errorf("sigLabel not specified")
	default:
		sigLabel = hmv.sigLabel
		sig, err = msg.GetSignature(sigLabel)
	}

	return
}
