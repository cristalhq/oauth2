package oauth2

import (
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Token represents the credentials used to authorize the requests to access
// protected resources on the OAuth 2.0 provider's backend.
type Token struct {
	AccessToken  string      `json:"access_token"`            // AccessToken is the token that authorizes and authenticates the requests.
	TokenType    string      `json:"token_type,omitempty"`    // TokenType is the type of token. The Type method returns either this or "Bearer".
	RefreshToken string      `json:"refresh_token,omitempty"` // RefreshToken is a token that's used by the application to refresh the access token if it expires.
	Expiry       time.Time   `json:"expiry,omitempty"`        // Expiry is the expiration time of the access token.
	Raw          interface{} // Raw optionally contains extra metadata from the server when updating a token.
}

// Type returns t.TokenType if non-empty, else "Bearer".
func (t *Token) Type() string {
	switch {
	case strings.EqualFold(t.TokenType, "bearer"):
		return "Bearer"
	case strings.EqualFold(t.TokenType, "mac"):
		return "MAC"
	case strings.EqualFold(t.TokenType, "basic"):
		return "Basic"
	case t.TokenType != "":
		return t.TokenType
	default:
		return "Bearer"
	}
}

// Extra returns an extra field.
// Extra fields are key-value pairs returned by the server as a
// part of the token retrieval response.
func (t *Token) Extra(key string) interface{} {
	switch v := t.Raw.(type) {
	case map[string]interface{}:
		return v[key]

	case url.Values:
		value := v.Get(key)
		s := strings.TrimSpace(value)

		switch strings.Count(s, ".") {
		case 0:
			// Contains no "."; try to parse as int
			i, err := strconv.ParseInt(s, 10, 64)
			if err == nil {
				return i
			}
		case 1:
			// Contains a single "."; try to parse as float
			f, err := strconv.ParseFloat(s, 64)
			if err == nil {
				return f
			}
		}
		return value

	default:
		return nil
	}
}

// Valid reports whether t is non-nil, has an AccessToken, and is not expired.
func (t *Token) Valid() bool {
	return t != nil && t.AccessToken != "" && !t.IsExpired()
}

// timeNow is used only in Token.IsExpired, is always time.Now, except some tests.
var timeNow = time.Now

// expiryDelta determines how earlier a token should be considered
// expired than its actual expiration time. It is used to avoid late
// expirations due to client-server time mismatches.
const expiryDelta = 10 * time.Second

// IsExpired reports whether the token is expired.
func (t *Token) IsExpired() bool {
	if t.Expiry.IsZero() {
		return false
	}
	return t.Expiry.Round(0).Add(-expiryDelta).Before(timeNow())
}
