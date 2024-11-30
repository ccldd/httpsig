package verifier

import (
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

	// Parse and validate the signature parameters
	sigParams := sigInput.SignatureParameters()
	for _, p := range sigParams {
		switch pp := p.(type) {
		case httpsig.Created:
			pp.Tolerance = hmv.createdTolerance
		case httpsig.Expires:
			pp.Tolerance = hmv.expiredTolerance
		}

		if err = p.Validate(); err != nil {
			return
		}
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
