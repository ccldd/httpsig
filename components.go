package httpsig

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/dunglas/httpsfv"
)

const (
	DerivedComponentMethod        = "@method"
	DerivedComponentTargetUri     = "@target-uri"
	DerivedComponentAuthority     = "@authority"
	DerivedComponentScheme        = "@scheme"
	DerivedComponentRequestTarget = "@request-target"
	DerivedComponentPath          = "@path"
	DerivedComponentQuery         = "@query"
	DerivedComponentQueryParam    = "@query-param"
	DerivedComponentStatus        = "@status"

	ComponentSignatureParams = "@signature-params"
)

var (
	ErrMultipleQueryParamValues = errors.New("multiple query param values")
)

type Component struct {
	Name  string
	Value string
}

// @signature-params derived component
//
// https://datatracker.ietf.org/doc/html/rfc9421#name-signature-parameters
type SignatureParams struct {
	Components httpsfv.InnerList
}

// Marshal serialises the signature params. The result
// does not include "@signature-params: ".
func (sp *SignatureParams) Marshal() (string, error) {
	return httpsfv.Marshal(sp.Components)
}

// GetComponentValue returns a component's value.
// If the name starts with "@" then it is retrieved as a derived component
// otherwise it is retrieved from the headers.
func GetComponentValue(name string, msg HttpMessage) (string, error) {
	var err error
	val := ""

	if strings.HasPrefix("@", name) {
		switch {
		case name == DerivedComponentMethod:
			val, err = msg.Method(), nil
		case name == DerivedComponentTargetUri:
			val, err = msg.Url().String(), nil
		case name == DerivedComponentAuthority:
			val, err = msg.Url().Host, nil
		case name == DerivedComponentScheme:
			val, err = msg.Url().Scheme, nil
		case name == DerivedComponentRequestTarget:
			val, err = msg.Url().RequestURI(), nil
		case name == DerivedComponentPath:
		case name == DerivedComponentQuery:
			val, err = msg.Url().RawQuery, nil
		case strings.HasPrefix(name, DerivedComponentQueryParam):
			val, err = GetQueryParamComponentValue(name, msg)
		case name == DerivedComponentStatus:
			if _, ok := msg.(*HttpRequest); ok {
				return "", fmt.Errorf("request do not support @status")
			} else {
				val, err = strconv.Itoa(msg.Status()), nil
			}
		default:
			return "", fmt.Errorf("unknown derived component: %s", name)
		}
	} else if header := msg.Header().Get(name); header != "" {
		val, err = header, nil
	}

	return val, err
}

// GetQueryParamComponentValue returns the value of a "@query-param" derived component.
// name is expected to have the name of the query parameter, e.g. "@query-param";name="var".
// TODO: handle url encoded @query-param name
func GetQueryParamComponentValue(name string, msg HttpMessage) (string, error) {
	s := name[strings.Index(name, ";")+1:]
	parts := strings.SplitN(s, "=", 2)

	key, queryName := "", ""
	if len(parts) > 0 {
		key = parts[0]
	}
	if len(parts) > 1 {
		queryName = parts[1]
	}

	if key != "name" {
		return "", fmt.Errorf("invalid @query-param: %s", queryName)
	}

	query := msg.Url().Query()
	values, ok := query[key]
	value := ""
	if !ok {
		return "", fmt.Errorf("%s query param not found", queryName)
	} else if len(values) == 0 {
		value = ""
	} else if len(values) == 1 {
		value = values[0]
	} else if len(values) > 1 {
		return "", fmt.Errorf("%s query param has multiple values", queryName)
	}

	if strings.ContainsAny(value, "\r\n") {
		return "", fmt.Errorf("%s query param has multiline value", queryName)
	}

	return value, nil
}
