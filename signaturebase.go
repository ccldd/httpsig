package httpsig

import (
	"fmt"
	"strings"

	"github.com/dunglas/httpsfv"
)

type SignatureBase struct {
	// Keys is a slice of component names
	// excluding @signature-params. For @query-param,
	// there can be multiple so the key will have the
	// query param name
	//   "@query-param";name="var"
	//   "@query-param";name="bar"
	Keys []string

	// Lines is a map of component names to
	// its string value excluding @signature-params
	Lines map[string]string

	// SignatureParams is the @signature-params which is always
	// at the end of the signature base
	SignatureParams SignatureParams
}

func (sb *SignatureBase) Marshal() (string, error) {
	var stringBuilder strings.Builder

	// Components
	for _, k := range sb.Keys {
		if v, ok := sb.Lines[k]; ok {
			stringBuilder.WriteString(k)
			stringBuilder.WriteString(": ")
			stringBuilder.WriteString(v)
			stringBuilder.WriteRune('\n')
		}
	}

	// Signature parameters
	sp, err := sb.SignatureParams.Marshal()
	if err != nil {
		return "", fmt.Errorf("error marshalling signature base: %w", err)
	}
	stringBuilder.WriteString(ComponentSignatureParams)
	stringBuilder.WriteString(": ")
	stringBuilder.WriteString(sp)

	return stringBuilder.String(), nil
}

func NewSignatureBaseFromRequest(msg HttpMessage, components []string, sigParams []SignatureParameter) (*SignatureBase, error) {
	sb := SignatureBase{
		Keys:  make([]string, 0),
		Lines: make(map[string]string),
		SignatureParams: SignatureParams{
			Components: httpsfv.InnerList{
				Items:  make([]httpsfv.Item, 0),
				Params: httpsfv.NewParams(),
			},
		},
	}

	// Components
	for _, componentName := range components {
		if _, ok := sb.Lines[componentName]; ok {
			return nil, fmt.Errorf("duplicate component: %s", componentName)
		}

		val, err := GetComponentValue(componentName, msg)
		if err != nil {
			if isDerivedComponent(componentName) {
				return &sb, err
			}

			// a missing header is fine
			continue
		}

		sb.Keys = append(sb.Keys, componentName)
		sb.Lines[componentName] = val
		sb.SignatureParams.Components.Items = append(sb.SignatureParams.Components.Items, httpsfv.NewItem(componentName))
	}

	// Signature Parameters
	for _, sp := range sigParams {
		if name, val := sp.Name(), sp.Value(); name != "" && val != "" {
			sb.SignatureParams.Components.Params.Add(sp.Name(), sp.Value())
		}
	}

	return &sb, nil
}
