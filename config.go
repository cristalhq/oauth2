package oauth2

import (
	"bytes"
	"net/url"
	"strings"
)

// Config describes a 3-legged OAuth2 flow.
type Config struct {
	// ClientID is the application's ID.
	ClientID string

	// ClientSecret is the application's secret.
	ClientSecret string

	// AuthURL is a URL for authentication.
	AuthURL string

	// TokenURL is a URL for retrieving a token.
	TokenURL string

	// Mode represents how tokens are represented in requests.
	Mode Mode

	// RedirectURL is the URL to redirect users going through
	// the OAuth flow, after the resource owner's URLs.
	RedirectURL string

	// Scope specifies optional requested permissions.
	Scopes []string
}

// Mode represents how requests for tokens are authenticated to the server.
type Mode int

const (
	// ModeAutoDetect means to auto-detect which authentication style the provider wants
	// by trying both ways and caching the successful way for the future.
	ModeAutoDetect Mode = 0

	// ModeInParams sends the "client_id" and "client_secret" in the POST body
	// as application/x-www-form-urlencoded parameters.
	ModeInParams Mode = 1

	// ModeInHeader sends the client_id and client_password using HTTP Basic Authorization.
	// This is an optional style described in the OAuth2 RFC 6749 section 2.3.1.
	ModeInHeader Mode = 2
)

// AuthCodeURL returns a URL to OAuth 2.0 provider's consent page
// that asks for permissions for the required scopes explicitly.
//
// State is a token to protect the user from CSRF attacks. You must
// always provide a non-empty string and validate that it matches the
// the state query parameter on your redirect callback.
// See http://tools.ietf.org/html/rfc6749#section-10.12 for more info.
//
func (c *Config) AuthCodeURL(state string) string {
	return c.AuthCodeURLWithParams(state, nil)
}

func (c *Config) AuthCodeURLWithParams(state string, vals url.Values) string {
	var buf bytes.Buffer
	buf.WriteString(c.AuthURL)

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

	if strings.Contains(c.AuthURL, "?") {
		buf.WriteByte('&')
	} else {
		buf.WriteByte('?')
	}

	buf.WriteString(v.Encode())
	return buf.String()
}
