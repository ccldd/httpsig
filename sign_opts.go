package httpsig

import (
	"net/http"
)

type SignOptions struct {
	// The headers and derived components to be included
	// when calculating the signature.
	//
	// If the header does not exist in the request, then it will be ignored.
	//
	// Add "Content-Digest" header if you want to sign the HTTP content.
	// You can call SignBody() to do it for you.
	components []string

	signatureParameters []SignatureParameter

	// componentNames is used to determine if a component has already been added or not
	componentNames map[string]struct{}

	// componentNames is used to determine if a signature parameter has already been added or not
	parameterNames map[string]struct{}
}

func (o *SignOptions) addComponents(components ...string) *SignOptions {
	for _, c := range components {
		if _, ok := o.componentNames[c]; !ok {
			o.components = append(o.components, c)
			o.componentNames[c] = struct{}{}
		}
	}
	return o
}

func (o *SignOptions) addParameter(param SignatureParameter) *SignOptions {
	if _, ok := o.parameterNames[param.Name()]; !ok {
		o.signatureParameters = append(o.signatureParameters, param)
		o.parameterNames[param.Name()] = struct{}{}
	}
	return o
}

func (o *SignOptions) WithHeaders(headers ...string) *SignOptions {
	for _, h := range headers {
		canonicalised := http.CanonicalHeaderKey(h)
		o.addComponents(canonicalised)
	}
	return o
}

// SignBody adds the "Content-Length" and "Content-Digest" headers
func (o *SignOptions) SignBody() *SignOptions {
	o.WithHeaders("Content-Length", HeaderContentDigest)
	return o
}

func (o *SignOptions) WithCreated() *SignOptions {
	o.addParameter(Created{})
	return o
}

func (o *SignOptions) WithExpires() *SignOptions {
	o.addParameter(Expires{})
	return o
}

func (o *SignOptions) WithNonce() *SignOptions {
	o.addParameter(Nonce(""))
	return o
}

func (o *SignOptions) WithAlg() *SignOptions {
	o.addParameter(Alg(""))
	return o
}

func (o *SignOptions) WithCustomAlg(alg string) *SignOptions {
	o.addParameter(Alg(alg))
	return o
}

func (o *SignOptions) WithKeyId(keyId string) *SignOptions {
	o.addParameter(KeyId(keyId))
	return o
}
