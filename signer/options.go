package signer

import (
	"net/http"

	"github.com/ccldd/httpsig"
)

type Option func(*HttpMessageSigner)

func withComponent(component string) Option {
	return func(hms *HttpMessageSigner) {
		for i, v := range hms.components {
			if v == component {
				hms.components = append(hms.components[:i], hms.components[i+1:]...)
				break
			}
		}
		hms.components = append(hms.components, component)
	}
}

func WithAuthority() Option {
	return withComponent(httpsig.DerivedComponentAuthority)
}

func WithMethod() Option {
	return withComponent(httpsig.DerivedComponentMethod)
}

func WithPath() Option {
	return withComponent(httpsig.DerivedComponentPath)
}

func WithQuery() Option {
	return withComponent(httpsig.DerivedComponentQuery)
}

func WithQueryParam() Option {
	return withComponent(httpsig.DerivedComponentQueryParam)
}

func WithRequestTarget() Option {
	return withComponent(httpsig.DerivedComponentRequestTarget)
}

func WithScheme() Option {
	return withComponent(httpsig.DerivedComponentScheme)
}

func WithStatus() Option {
	return withComponent(httpsig.DerivedComponentStatus)
}

func WithTargetUri() Option {
	return withComponent(httpsig.DerivedComponentTargetUri)
}

// WithHeaders adds headers (canonicalized) to the components
func WithHeaders(headers ...string) Option {
	return func(hms *HttpMessageSigner) {
		for _, h := range headers {
			canonicalized := http.CanonicalHeaderKey(h)
			withComponent(canonicalized)(hms)
		}
	}
}

// SignBody adds "Content-Length" and "Content-Digest" headers as components
// if there is a body
func SignBody() Option {
	return WithHeaders("Content-Length", httpsig.HeaderContentDigest)
}

// withParameter adds a signature parameter to SignOptions
func withParameter(param httpsig.SignatureParameter) Option {
	return func(hms *HttpMessageSigner) {
		for i, v := range hms.signatureParameters {
			if v.Name() == param.Name() {
				hms.signatureParameters = append(hms.signatureParameters[:i], hms.signatureParameters[i+1:]...)
				break
			}
		}
		hms.signatureParameters = append(hms.signatureParameters, param)
	}
}

// WithCreated adds the "Created" signature parameter
func WithCreated() Option {
	return withParameter(httpsig.Created{})
}

// WithExpires adds the "Expires" signature parameter
func WithExpires() Option {
	return withParameter(httpsig.Expires{})
}

// WithNonce adds the "Nonce" signature parameter
func WithNonce() Option {
	return withParameter(httpsig.Nonce(""))
}

// WithAlg adds the "Alg" signature parameter and automatically gets the value
// based on the signing algorithm and hash used
func WithAlg() Option {
	return withParameter(httpsig.Alg(""))
}

// WithCustomAlg adds the "Alg" signature parameter with a custom value
func WithCustomAlg(alg string) Option {
	return withParameter(httpsig.Alg(alg))
}

// WithKeyId adds a specific key ID to the signature parameters
func WithKeyId(keyId string) Option {
	return withParameter(httpsig.KeyId(keyId))
}
