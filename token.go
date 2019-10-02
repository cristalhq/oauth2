// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package oauth2

import (
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Token represents the credentials used to authorize the requests to access
// protected resources on the OAuth 2.0 provider's backend.
//
type Token struct {
	// AccessToken is the token that authorizes and authenticates the requests.
	AccessToken string `json:"access_token"`

	// TokenType is the type of token.
	// The Type method returns either this or "Bearer".
	TokenType string `json:"token_type,omitempty"`

	// RefreshToken is a token that's used by the application
	// (as opposed to the user) to refresh the access token if it expires.
	RefreshToken string `json:"refresh_token,omitempty"`

	// Expiry is the optional expiration time of the access token.
	//
	// If zero, TokenSource implementations will reuse the same
	// token forever and RefreshToken or equivalent
	// mechanisms for that TokenSource will not be used.
	Expiry time.Time `json:"expiry,omitempty"`

	// raw optionally contains extra metadata from the server when updating a token.
	raw interface{}
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

// WithExtra returns a new Token that's a clone of t, but using the
// provided raw extra map. This is only intended for use by packages
// implementing derivative OAuth2 flows.
func (t *Token) SetExtra(extra interface{}) *Token {
	t2 := new(Token)
	*t2 = *t
	t2.raw = extra
	return t2
}

// Extra returns an extra field.
// Extra fields are key-value pairs returned by the server as a
// part of the token retrieval response.
func (t *Token) Extra(key string) interface{} {
	switch v := t.raw.(type) {
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
//
func (t *Token) Valid() bool {
	return t != nil && t.AccessToken != "" && !t.IsExpired()
}

// timeNow is always time.Now, except tests.
// is used only in Token.IsExpired
var timeNow = time.Now

// expiryDelta determines how earlier a token should be considered
// expired than its actual expiration time. It is used to avoid late
// expirations due to client-server time mismatches.
const expiryDelta = 10 * time.Second

// IsExpired reports whether the token is expired.
//
func (t *Token) IsExpired() bool {
	if t.Expiry.IsZero() {
		return false
	}
	return t.Expiry.Round(0).Add(-expiryDelta).Before(timeNow())
}
