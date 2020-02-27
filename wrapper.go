package oauth2

import (
	"net/http"
)

// Wrap adds an additional header to the given http.Client.
// The header will be `Authorization`.
// All the params cannot be empty or nil.
//
func Wrap(header, value string, c *http.Client) (*http.Client, error) {
	transport := http.DefaultTransport
	if c.Transport != nil {
		transport = c.Transport
	}

	wrapped := &http.Client{
		Transport: &wrappedTransport{
			header:    header,
			value:     value,
			transport: transport,
		},
	}
	return wrapped, nil
}

type wrappedTransport struct {
	header    string
	value     string
	transport http.RoundTripper
}

// RoundTrip implements the http.RoundTripper interface.
func (t *wrappedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = cloneRequest(req)
	req.Header.Set(t.header, t.value)
	return t.transport.RoundTrip(req)
}

func cloneRequest(r *http.Request) *http.Request {
	r2 := &http.Request{}
	*r2 = *r
	r2.Header = make(http.Header, len(r.Header))
	for k, s := range r.Header {
		r2.Header[k] = append([]string(nil), s...)
	}
	return r2
}
