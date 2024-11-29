package httpsig

import (
	"net/http"
	"net/url"
)

// HttpMessage is a wrapper for http.Request or http.Response
// so we can access common struct fields
type HttpMessage interface {
	Url() *url.URL
	Method() string
	Header() http.Header
	Status() int
}

type HttpRequest struct {
	Request *http.Request
}

func (hr *HttpRequest) Url() *url.URL {
	return hr.Request.URL
}

func (hr *HttpRequest) Method() string {
	return hr.Request.Method
}

func (hr *HttpRequest) Header() http.Header {
	return hr.Request.Header
}

func (hr *HttpRequest) Status() int {
	return 0 // requests do not have status
}

type HttpResponse struct {
	*http.Response
}

func (hr *HttpResponse) Url() *url.URL {
	return hr.Response.Request.URL
}

func (hr *HttpResponse) Method() string {
	return hr.Response.Request.Method
}

func (hr *HttpResponse) Header() http.Header {
	return hr.Response.Header
}

func (hr *HttpResponse) Status() int {
	return hr.StatusCode
}
