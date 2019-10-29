package oauth2

import (
	"bytes"
	"net/url"
	"strings"
)

// Config describes a 3-legged OAuth2 flow.
type Config struct {
	ClientID     string   // ClientID is the application's ID.
	ClientSecret string   // ClientSecret is the application's secret.
	AuthURL      string   // AuthURL is a URL for authentication.
	TokenURL     string   // TokenURL is a URL for retrieving a token.
	Mode         Mode     // Mode represents how tokens are represented in requests.
	RedirectURL  string   // RedirectURL is the URL to redirect users going through the OAuth flow.
	Scopes       []string // Scope specifies optional requested permissions.
}

// Mode represents how requests for tokens are authenticated to the server.
type Mode int

const (
	// AutoDetectMode means to auto-detect which authentication style the provider wants.
	AutoDetectMode Mode = 0

	// InParamsMode sends the `client_id` and `client_secret` in the POST body
	// as application/x-www-form-urlencoded parameters.
	InParamsMode Mode = 1

	// InHeaderMode sends the `client_id` and `client_secret` using HTTP Basic Authorization.
	// This is an optional style described in the OAuth2 RFC 6749 section 2.3.1.
	InHeaderMode Mode = 2
)

// AuthCodeURL returns a URL to OAuth 2.0 provider's consent page
// that asks for permissions for the required scopes explicitly.
//
// State is a token to protect the user from CSRF attacks.
//
// You must always provide a non-empty string and validate that it matches the
// the state query parameter on your redirect callback.
//
// See http://tools.ietf.org/html/rfc6749#section-10.12 for more info.
//
func (c *Config) AuthCodeURL(state string) string {
	return c.AuthCodeURLWithParams(state, nil)
}

// AuthCodeURLWithParams same as AuthCodeURL but allows to pass additional URL parameters.
func (c *Config) AuthCodeURLWithParams(state string, vals url.Values) string {
	v := cloneURLValues(vals)
	v.Add("response_type", "code")
	v.Add("client_id", c.ClientID)

	if c.RedirectURL != "" {
		v.Set("redirect_uri", c.RedirectURL)
	}
	if len(c.Scopes) > 0 {
		v.Set("scope", strings.Join(c.Scopes, " "))
	}
	if state != "" {
		v.Set("state", state)
	}

	var buf bytes.Buffer
	buf.WriteString(c.AuthURL)

	if strings.Contains(c.AuthURL, "?") {
		buf.WriteByte('&')
	} else {
		buf.WriteByte('?')
	}

	buf.WriteString(v.Encode())
	return buf.String()
}
