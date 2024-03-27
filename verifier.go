package httpsig

import "net/http"

type Verifier interface {
	VerifyRequest(req http.Request)
}

// HttpMessageVerifier implements Verifier
// using VerifyingAlgorithm
type HttpMessageVerifier struct {

}