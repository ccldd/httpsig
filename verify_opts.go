package httpsig

type VerifyOptions struct {
	// Algorithms are the supported
	Algorithms map[string]VerifyingAlgorithm

	// The keyids that are supported
	KeyIds map[string]struct{}

	// SignaturePickFunc is a function that returns
	// the signature label that will be verified
	SignaturePickFunc func([]string) string

	CanVerifyFunc func(SignatureInput) string
}

func (vo VerifyOptions) SupportsAlg(alg string) bool {
	_, ok := vo.Algorithms[alg]
	return ok
}
