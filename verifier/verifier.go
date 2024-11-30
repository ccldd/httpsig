package verifier

import (
	"fmt"
	"net/http"

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

	// Parse the signature parameters
	httpsig.SignatureBase

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
