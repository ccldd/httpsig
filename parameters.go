package httpsig

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const (
	SignatureParameterCreated = "created"
	SignatureParameterExpires = "expired"
	SignatureParameterNonce   = "nonce"
	SignatureParameterAlg     = "alg"
	SignatureParameterKeyId   = "keyid"
	SignatureParameterTag     = "tag"
)

type SignatureParameter interface {
	fmt.Stringer
	Name() string
	Value() any
	Validate() error
}

// Created is the created signature parameter
// which is the unix timestamp in seconds in which
// the signature was generated. If the value is 0,
// then the current system time is used as the value.
type Created struct {
	Time      time.Time
	Tolerance time.Duration
}

func (c Created) Name() string {
	return SignatureParameterCreated
}

func (c Created) Value() any {
	if c.Time.IsZero() {
		return time.Now().UTC().Unix()
	}

	return c.Time.Unix()
}

func (c Created) Validate() error {
	now := time.Now().UTC()
	if c.Time.Add(-c.Tolerance).Before(now) {
		return fmt.Errorf("signature created is not yet valid, will be valid at %s", c.Time.Local())
	}

	return nil
}

func (c Created) String() string {
	return fmt.Sprintf("%s=%d", c.Name(), c.Value())
}

func CreatedFromString(s string) (Created, error) {
	tokens := strings.SplitN(s, "=", 2)
	if len(tokens) != 2 {
		return Created{}, fmt.Errorf("invalid created signature parameter: %s", s)
	}

	seconds, err := strconv.ParseInt(tokens[1], 10, 64)
	if err != nil {
		return Created{}, fmt.Errorf("invalid created signature parameter: %w", err)
	}

	t := time.Unix(seconds, 0)
	return Created{Time: t, Tolerance: 0}, nil
}

// Expires is the expired signature parameter
// which is the unix timestamp in seconds in which
// the signature will be expired.
type Expires struct {
	Time      time.Time
	Tolerance time.Duration
}

func (c Expires) Name() string {
	return SignatureParameterExpires
}

func (c Expires) Value() any {
	return c.Time.Unix()
}

func (c Expires) Validate() error {
	now := time.Now().UTC()
	if c.Time.Add(c.Tolerance).After(now) {
		return fmt.Errorf("signature expires is expired, expired at %s", c.Time.Local())
	}

	return nil
}

func (c Expires) String() string {
	return fmt.Sprintf("%s=%d", c.Name(), c.Value())
}

func ExpiredFromString(s string) (Expires, error) {
	tokens := strings.SplitN(s, "=", 2)
	if len(tokens) != 2 {
		return Expires{}, fmt.Errorf("invalid expires signature parameter: %s", s)
	}

	seconds, err := strconv.ParseInt(tokens[1], 10, 64)
	if err != nil {
		return Expires{}, fmt.Errorf("invalid expires signature parameter: %w", err)
	}

	t := time.Unix(seconds, 0)
	return Expires{Time: t, Tolerance: 0}, nil
}

type Nonce string

func (k Nonce) Name() string {
	return SignatureParameterNonce
}

func (k Nonce) Value() any {
	if k == "" {
		bytes := make([]byte, 128)
		rand.Read(bytes)
		encoded := base64.StdEncoding.EncodeToString(bytes)
		return encoded
	}

	return string(k)
}

func (c Nonce) String() string {
	return fmt.Sprintf("%s=\"%s\"", c.Name(), c.Value())
}

func (k Nonce) Validate() error {
	if k.Value() == "" {
		return fmt.Errorf("nonce has no value")
	}

	return nil
}

type Alg string

func (k Alg) Name() string {
	return SignatureParameterAlg
}

func (k Alg) Value() any {
	return string(k)
}

func (c Alg) String() string {
	return fmt.Sprintf("%s=\"%s\"", c.Name(), c.Value())
}

func (k Alg) Validate() error {
	if k.Value() == "" {
		return fmt.Errorf("alg has no value")
	}

	return nil
}

type KeyId string

func (k KeyId) Name() string {
	return SignatureParameterKeyId
}

func (k KeyId) Value() any {
	return string(k)
}

func (c KeyId) String() string {
	return fmt.Sprintf("%s=\"%s\"", c.Name(), c.Value())
}

func (k KeyId) Validate() error {
	if k.Value() == "" {
		return fmt.Errorf("keyid has no value")
	}

	return nil
}

type Tag string

func (k Tag) Name() string {
	return SignatureParameterTag
}

func (k Tag) Value() any {
	return string(k)
}

func (c Tag) String() string {
	return fmt.Sprintf("%s=\"%s\"", c.Name(), c.Value())
}

func (k Tag) Validate() error {
	if k.Value() == "" {
		return fmt.Errorf("tag has no value")
	}

	return nil
}
