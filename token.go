// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package oauth2

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/context/ctxhttp"
)

// expiryDelta determines how earlier a token should be considered
// expired than its actual expiration time. It is used to avoid late
// expirations due to client-server time mismatches.
const expiryDelta = 10 * time.Second

// Token represents the credentials used to authorize
// the requests to access protected resources on the OAuth 2.0
// provider's backend.
//
// Most users of this package should not access fields of Token
// directly. They're exported mostly for use by related packages
// implementing derivative OAuth2 flows.
type Token struct {
	// AccessToken is the token that authorizes and authenticates the requests.
	AccessToken string `json:"access_token"`

	// TokenType is the type of token.
	// The Type method returns either this or "Bearer", the default.
	TokenType string `json:"token_type,omitempty"`

	// RefreshToken is a token that's used by the application
	// (as opposed to the user) to refresh the access token
	// if it expires.
	RefreshToken string `json:"refresh_token,omitempty"`

	// Expiry is the optional expiration time of the access token.
	//
	// If zero, TokenSource implementations will reuse the same
	// token forever and RefreshToken or equivalent
	// mechanisms for that TokenSource will not be used.
	Expiry time.Time `json:"expiry,omitempty"`

	// Raw optionally contains extra metadata from the server when updating a token.
	Raw interface{}
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

// SetAuthHeader sets the Authorization header to r using the access
// token in t.
//
// This method is unnecessary when using Transport or an HTTP Client
// returned by this package.
func (t *Token) SetAuthHeader(r *http.Request) {
	r.Header.Set("Authorization", t.Type()+" "+t.AccessToken)
}

// WithExtra returns a new Token that's a clone of t, but using the
// provided raw extra map. This is only intended for use by packages
// implementing derivative OAuth2 flows.
func (t *Token) WithExtra(extra interface{}) *Token {
	t2 := new(Token)
	*t2 = *t
	t2.Raw = extra
	return t2
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

// timeNow is time.Now but pulled out as a variable for tests.
var timeNow = time.Now

// expired reports whether the token is expired.
// t must be non-nil.
func (t *Token) expired() bool {
	if t.Expiry.IsZero() {
		return false
	}
	return t.Expiry.Round(0).Add(-expiryDelta).Before(timeNow())
}

// Valid reports whether t is non-nil, has an AccessToken, and is not expired.
func (t *Token) Valid() bool {
	return t != nil && t.AccessToken != "" && !t.expired()
}

// retrieveToken takes a *Config and uses that to retrieve an *internal.Token.
// This token is then mapped from *internal.Token into an *oauth2.Token which is returned along
// with an error..
func retrieveToken(ctx context.Context, c *Config, v url.Values) (*Token, error) {
	tk, err := RetrieveToken(ctx, c.ClientID, c.ClientSecret, c.TokenURL, v, AuthStyle(c.AuthStyle))
	if err != nil {
		if rErr, ok := err.(*Error); ok {
			return nil, (*Error)(rErr)
		}
		return nil, err
	}
	return tk, nil
}

// tokenJSON is the struct representing the HTTP response from OAuth2
// providers returning a tokenw in JSON form.
type tokenJSON struct {
	AccessToken  string         `json:"access_token"`
	TokenType    string         `json:"token_type"`
	RefreshToken string         `json:"refresh_token"`
	ExpiresIn    expirationTime `json:"expires_in"` // at least PayPal returns string, while most return number
}

func (e *tokenJSON) expiry() (t time.Time) {
	if v := e.ExpiresIn; v != 0 {
		return time.Now().Add(time.Duration(v) * time.Second)
	}
	return
}

type expirationTime int32

func (e *expirationTime) UnmarshalJSON(b []byte) error {
	if len(b) == 0 || string(b) == "null" {
		return nil
	}
	var n json.Number
	err := json.Unmarshal(b, &n)
	if err != nil {
		return err
	}
	i, err := n.Int64()
	if err != nil {
		return err
	}
	if i > math.MaxInt32 {
		i = math.MaxInt32
	}
	*e = expirationTime(i)
	return nil
}

// TODOs
func RetrieveToken(ctx context.Context, clientID, clientSecret, tokenURL string, v url.Values, authStyle AuthStyle) (*Token, error) {
	needsAuthStyleProbe := authStyle == 0
	if needsAuthStyleProbe {
		// if style, ok := lookupAuthStyle(tokenURL); ok {
		// 	authStyle = style
		// 	needsAuthStyleProbe = false
		// } else {
		// 	authStyle = AuthStyleInHeader // the first way we'll try
		// }
		authStyle = AuthStyleInHeader // the first way we'll try
	}
	req, err := newTokenRequest(tokenURL, clientID, clientSecret, v, authStyle)
	if err != nil {
		return nil, err
	}
	token, err := doTokenRoundTrip(ctx, req)
	if err != nil && needsAuthStyleProbe {
		// If we get an error, assume the server wants the
		// clientID & clientSecret in a different form.
		// See https://code.google.com/p/goauth2/issues/detail?id=31 for background.
		// In summary:
		// - Reddit only accepts client secret in the Authorization header
		// - Dropbox accepts either it in URL param or Auth header, but not both.
		// - Google only accepts URL param (not spec compliant?), not Auth header
		// - Stripe only accepts client secret in Auth header with Bearer method, not Basic
		//
		// We used to maintain a big table in this code of all the sites and which way
		// they went, but maintaining it didn't scale & got annoying.
		// So just try both ways.
		authStyle = AuthStyleInParams // the second way we'll try
		req, _ = newTokenRequest(tokenURL, clientID, clientSecret, v, authStyle)
		token, err = doTokenRoundTrip(ctx, req)
	}
	// if needsAuthStyleProbe && err == nil {
	// 	setAuthStyle(tokenURL, authStyle)
	// }

	// Don't overwrite `RefreshToken` with an empty value
	// if this was a token refreshing request.
	if token != nil && token.RefreshToken == "" {
		token.RefreshToken = v.Get("refresh_token")
	}
	return token, err
}

func doTokenRoundTrip(ctx context.Context, req *http.Request) (*Token, error) {
	r, err := ctxhttp.Do(ctx, ContextClient(ctx), req)
	if err != nil {
		return nil, err
	}

	body, err := ioutil.ReadAll(io.LimitReader(r.Body, 1<<20))
	r.Body.Close()

	if err != nil {
		return nil, fmt.Errorf("oauth2: cannot fetch token: %v", err)
	}
	if code := r.StatusCode; code < 200 || code > 299 {
		return nil, &Error{
			Response: r,
			Body:     body,
		}
	}

	var token *Token
	content, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	switch content {
	case "application/x-www-form-urlencoded", "text/plain":
		vals, err := url.ParseQuery(string(body))
		if err != nil {
			return nil, err
		}
		token = &Token{
			AccessToken:  vals.Get("access_token"),
			TokenType:    vals.Get("token_type"),
			RefreshToken: vals.Get("refresh_token"),
			Raw:          vals,
		}
		e := vals.Get("expires_in")
		expires, _ := strconv.Atoi(e)
		if expires != 0 {
			token.Expiry = time.Now().Add(time.Duration(expires) * time.Second)
		}
	default:
		var tj tokenJSON
		if err = json.Unmarshal(body, &tj); err != nil {
			return nil, err
		}
		token = &Token{
			AccessToken:  tj.AccessToken,
			TokenType:    tj.TokenType,
			RefreshToken: tj.RefreshToken,
			Expiry:       tj.expiry(),
			Raw:          make(map[string]interface{}),
		}
		_ = json.Unmarshal(body, &token.Raw) // no error checks for optional fields
	}
	if token.AccessToken == "" {
		return nil, errors.New("oauth2: server response missing access_token")
	}
	return token, nil
}
