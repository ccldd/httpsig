package signer

import (
	"fmt"
)

type SigningError struct {
}

func (e SigningError) Error() string {
	return fmt.Sprintf("error signing HTTP message")
}
