package httpsig

import (
	"reflect"
	"time"

	"github.com/dunglas/httpsfv"
)

const (
	HeaderContentDigest = "Content-Digest"

	HeaderSignature      = "Signature"
	HeaderSignatureInput = "Signature-Input"
)

type SignatureHeaderValue httpsfv.Dictionary

func NewSignatureHeaderValue(sigLabel string, signature []byte) SignatureHeaderValue {
	d := httpsfv.NewDictionary()
	d.Add(sigLabel, httpsfv.NewItem(signature))
	sig := SignatureHeaderValue(*d)
	return sig
}

func ParseSignatureHeaderValue(s string) (sig SignatureHeaderValue, err error) {
	d, err := httpsfv.UnmarshalDictionary([]string{s})
	if err != nil {
		return
	}

	sig = SignatureHeaderValue(*d)
	return
}

func (sig SignatureHeaderValue) Marshal() (s string, err error) {
	d := httpsfv.Dictionary(sig)
	s, err = httpsfv.Marshal(&d)
	return
}

// signatureInput is a Dictionary Structured Field containing
// the metadata for one or more message signatures generated
// from components within the HTTP message.
//
// It is a HTTP header with the key "Signature-Input".
//
// The value is very similar to the value of @signature-params but the component list
// has a key which is the label for the signature.
//
// Example:
//
//	Signature-Input: sig1=("@method" "@target-uri" "@authority" \
//	  "content-digest" "cache-control");\
//	  created=1618884475;keyid="test-key-rsa-pss"
//
// https://datatracker.ietf.org/doc/html/rfc9421#name-the-signature-input-http-fi
type SignatureInput httpsfv.Dictionary

func ParseSignatureInput(s string) (sigInput SignatureInput, err error) {
	d, err := httpsfv.UnmarshalDictionary([]string{s})
	if err != nil {
		return
	}

	sigInput = SignatureInput(*d)
	return
}

func (si SignatureInput) Marshal() (string, error) {
	d := httpsfv.Dictionary(si)
	return httpsfv.Marshal(&d)
}

func (si SignatureInput) GetStringValue(key string) (val string, found bool) {
	d := httpsfv.Dictionary(si)
	var m httpsfv.Member
	m, found = d.Get(key)
	if !found {
		return
	}

	val, _ = httpsfv.Marshal(m)
	return
}

func (si SignatureInput) SigLabel() string {
	d := httpsfv.Dictionary(si)
	if len(d.Names()) < 1 {
		return ""
	}

	sigLabel := d.Names()[0]
	return sigLabel
}

func (si SignatureInput) SignatureParameters() []SignatureParameter {
	params := make([]SignatureParameter, 0)

	d := httpsfv.Dictionary(si)
	m, found := d.Get(si.SigLabel())
	if !found {
		return params
	}

	innerList, ok := m.(httpsfv.InnerList)
	if !ok {
		return params
	}

	for _, k := range innerList.Params.Names() {
		val, _ := innerList.Params.Get(k)
		switch k {
		case SignatureParameterCreated:
			if v, ok := val.(int64); ok {
				params = append(params, Created{Time: time.Unix(v, 0)})
			}
		case SignatureParameterExpires:
			if v, ok := val.(int64); ok {
				params = append(params, Expires{Time: time.Unix(v, 0)})
			}
		case SignatureParameterNonce:
			if v, ok := val.(string); ok {
				params = append(params, Nonce(v))
			}
		case SignatureParameterAlg:
			if v, ok := val.(string); ok {
				params = append(params, Alg(v))
			}
		case SignatureParameterKeyId:
			if v, ok := val.(string); ok {
				params = append(params, KeyId(v))
			}
		case SignatureParameterTag:
			if v, ok := val.(string); ok {
				params = append(params, Tag(v))
			}
		}
	}

	return params
}

func (si SignatureInput) Alg() (string, bool) {
	return si.GetStringValue(SignatureParameterAlg)
}

func (si SignatureInput) Created() (string, bool) {
	return si.GetStringValue(SignatureParameterCreated)
}

func (si SignatureInput) Expires() (string, bool) {
	return si.GetStringValue(SignatureParameterExpires)
}

func (si SignatureInput) KeyId() (string, bool) {
	return si.GetStringValue(SignatureParameterKeyId)
}

func (si SignatureInput) Nonce() (string, bool) {
	return si.GetStringValue(SignatureParameterNonce)
}

func (si SignatureInput) Tag() (string, bool) {
	return si.GetStringValue(SignatureParameterTag)
}

func SignatureInputFromSignatureParams(sigLabel string, sp *SignatureParams) *SignatureInput {
	dict := httpsfv.NewDictionary()

	innerList := httpsfv.InnerList{
		Items:  make([]httpsfv.Item, len(sp.Components.Items)),
		Params: httpsfv.NewParams(),
	}

	for i, item := range innerList.Items {
		clonedVal := reflect.ValueOf(item.Value)
		innerList.Items[i] = httpsfv.Item{Value: clonedVal}
	}

	for _, name := range sp.Components.Params.Names() {
		if v, ok := sp.Components.Params.Get(name); ok {
			innerList.Params.Add(name, httpsfv.NewItem(v))
		}
	}

	dict.Add(sigLabel, innerList)

	si := SignatureInput(*dict)
	return &si
}
