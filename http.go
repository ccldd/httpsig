package httpsig

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// HttpMessage is a wrapper for http.Request or http.Response
// so we can access common struct fields
type HttpMessage interface {
	Url() *url.URL
	Method() string
	Header() http.Header
	Status() int
}

type SignedHttpMessage interface {
	SigLabels() []string
	GetSignature(sigLabel string) (SignatureHeaderValue, error)
	GetSignatureInput(sigLabel string) (SignatureInput, error)
}

type HttpRequest struct {
	Request *http.Request
}

func (hr HttpRequest) Url() *url.URL {
	return hr.Request.URL
}

func (hr HttpRequest) Method() string {
	return hr.Request.Method
}

func (hr HttpRequest) Header() http.Header {
	return hr.Request.Header
}

func (hr HttpRequest) Status() int {
	return 0 // requests do not have status
}

func (hr HttpRequest) SigLabels() []string {
	labels := make([]string, 0)
	vals := hr.Request.Header.Values(HeaderSignature)
	for _, v := range vals {
		if label, _, found := strings.Cut(v, "="); found {
			labels = append(labels, label)
		}
	}

	return labels
}

func (hr HttpRequest) GetSignature(sigLabel string) (sig SignatureHeaderValue, err error) {
	var found bool

	vals := hr.Request.Header.Values(HeaderSignature)
	for _, v := range vals {
		var label, headerValue string
		var ok bool
		if label, headerValue, ok = strings.Cut(v, "="); ok && label == sigLabel {
			found = true
			sig, _ = ParseSignatureHeaderValue(headerValue)
		}
	}

	if found {
		err = fmt.Errorf("failed to parse signature")
	} else {
		err = fmt.Errorf("signature '%s' not found", sigLabel)
	}

	return
}

func (hr HttpRequest) GetSignatureInput(sigLabel string) (sigInput SignatureInput, err error) {
	var found bool

	vals := hr.Request.Header.Values(HeaderSignature)
	for _, v := range vals {
		var label, headerValue string
		var ok bool
		if label, headerValue, ok = strings.Cut(v, "="); ok && label == sigLabel {
			found = true
			sigInput, _ = ParseSignatureInput(headerValue)
		}
	}

	if found {
		err = fmt.Errorf("failed to parse signature-input")
	} else {
		err = fmt.Errorf("signature-input '%s' not found", sigLabel)
	}

	return
}

type HttpResponse struct {
	*http.Response
}

func (hr *HttpResponse) Url() *url.URL {
	return hr.Response.Request.URL
}

func (hr *HttpResponse) Method() string {
	return hr.Response.Request.Method
}

func (hr *HttpResponse) Header() http.Header {
	return hr.Response.Header
}

func (hr *HttpResponse) Status() int {
	return hr.StatusCode
}
