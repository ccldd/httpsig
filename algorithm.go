package httpsig

type Algorithm interface {
	// The algorithm name which is also the value used
	// for the alg signature parameter
	//
	// https://datatracker.ietf.org/doc/html/rfc9421#name-initial-contents
	Name() string
}
