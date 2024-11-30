package httpsig

import (
	"reflect"

	"github.com/dunglas/httpsfv"
)

const (
	HeaderContentDigest = "Content-Digest"

	HeaderSignature      = "Signature"
	HeaderSignatureInput = "Signature-Input"
)

func SignatureHeaderValue(sigLabel string, signature []byte) (string, error) {
	d := httpsfv.NewDictionary()
	d.Add(sigLabel, httpsfv.NewItem(signature))

	v, err := httpsfv.Marshal(d)
	if err != nil {
		return "", err
	}

	return v, nil
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
// https://datatracker.ietf.org/doc/html/rfc9421#name-the-signature-input-http-fi
type SignatureInput httpsfv.Dictionary

func (si SignatureInput) Marshal() (string, error) {
	d := httpsfv.Dictionary(si)
	return httpsfv.Marshal(&d)
}

func SignatureInputFromSignatureParams(sigLabel string, sp *SignatureParams) *SignatureInput {
	dict := httpsfv.NewDictionary()

	components := httpsfv.InnerList{
		Items: make([]httpsfv.Item, len(sp.Components.Items)),
	}

	for i, item := range components.Items {
		clonedVal := reflect.ValueOf(item.Value)
		components.Items[i] = httpsfv.Item{Value: clonedVal}
	}

	dict.Add(sigLabel, components)
	for _, name := range sp.Components.Params.Names() {
		if v, ok := sp.Components.Params.Get(name); ok {
			dict.Add(name, httpsfv.NewItem(v))
		}
	}
	si := SignatureInput(*dict)
	return &si
}
