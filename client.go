package oauth2

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

// Client represents an OAuth2 HTTP client.
type Client struct {
	client *http.Client
	config Config
}

// NewClient instantiates a new client with a given config.
func NewClient(client *http.Client, config Config) *Client {
	c := &Client{
		client: client,
		config: config,
	}
	return c
}

// AuthCodeURL returns a URL to OAuth 2.0 provider's consent page
// that asks for permissions for the required scopes explicitly.
//
// State is a token to protect the user from CSRF attacks.
//
// You must always provide a non-empty string and validate that it matches the
// the state query parameter on your redirect callback.
//
// See http://tools.ietf.org/html/rfc6749#section-10.12 for more info.
func (c *Client) AuthCodeURL(state string) string {
	return c.AuthCodeURLWithParams(state, nil)
}

// AuthCodeURLWithParams same as AuthCodeURL but allows to pass additional URL parameters.
func (c *Client) AuthCodeURLWithParams(state string, params url.Values) string {
	// TODO(cristaloleg): can be set once (except state).
	v := cloneURLValues(params)
	v.Add("response_type", "code")
	v.Add("client_id", c.config.ClientID)

	if c.config.RedirectURL != "" {
		v.Set("redirect_uri", c.config.RedirectURL)
	}
	if len(c.config.Scopes) > 0 {
		v.Set("scope", strings.Join(c.config.Scopes, " "))
	}
	if state != "" {
		v.Set("state", state)
	}

	var buf bytes.Buffer
	buf.WriteString(c.config.AuthURL)

	if strings.Contains(c.config.AuthURL, "?") {
		buf.WriteByte('&')
	} else {
		buf.WriteByte('?')
	}

	buf.WriteString(v.Encode())
	return buf.String()
}

// Exchange converts an authorization code into an OAuth2 token.
func (c *Client) Exchange(ctx context.Context, code string) (*Token, error) {
	return c.ExchangeWithParams(ctx, code, nil)
}

// ExchangeWithParams converts an authorization code into an OAuth2 token.
func (c *Client) ExchangeWithParams(ctx context.Context, code string, params url.Values) (*Token, error) {
	params = cloneURLValues(params)
	params.Add("grant_type", "authorization_code")
	params.Add("code", code)

	if c.config.RedirectURL != "" {
		params.Set("redirect_uri", c.config.RedirectURL)
	}
	return c.retrieveToken(ctx, params)
}

// CredentialsToken retrieves a token for given username and password.
func (c *Client) CredentialsToken(ctx context.Context, username, password string) (*Token, error) {
	params := url.Values{
		"grant_type": []string{"password"},
		"username":   []string{username},
		"password":   []string{password},
	}

	if len(c.config.Scopes) > 0 {
		params.Set("scope", strings.Join(c.config.Scopes, " "))
	}
	return c.retrieveToken(ctx, params)
}

// Token renews a token based on previous token.
func (c *Client) Token(ctx context.Context, refreshToken string) (*Token, error) {
	if refreshToken == "" {
		return nil, errors.New("refresh token is not set")
	}

	params := url.Values{
		"grant_type":    []string{"refresh_token"},
		"refresh_token": []string{refreshToken},
	}
	return c.retrieveToken(ctx, params)
}

func (c *Client) retrieveToken(ctx context.Context, params url.Values) (*Token, error) {
	mode := c.config.Mode

	shouldGuessAuthMode := mode == AutoDetectMode
	if shouldGuessAuthMode {
		mode = InHeaderMode
	}

	token, err := c.doRequest(ctx, mode, params)
	if err == nil {
		c.config.Mode = mode
		return token, nil
	}
	if !shouldGuessAuthMode {
		return nil, err
	}
	mode = InParamsMode

	token, err = c.doRequest(ctx, mode, params)
	if err != nil {
		return nil, err
	}
	c.config.Mode = mode
	return token, nil
}

func (c *Client) doRequest(ctx context.Context, mode Mode, params url.Values) (*Token, error) {
	req, err := c.newTokenRequest(ctx, mode, params)
	if err != nil {
		return nil, err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}

	token, err := parseResponse(resp)
	if err != nil {
		return nil, err
	}
	return token, nil
}

func (c *Client) newTokenRequest(ctx context.Context, mode Mode, v url.Values) (*http.Request, error) {
	clientID, clientSecret := c.config.ClientID, c.config.ClientSecret

	if mode == InParamsMode {
		v = cloneURLValues(v)
		if clientID != "" {
			v.Set("client_id", clientID)
		}
		if clientSecret != "" {
			v.Set("client_secret", clientSecret)
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.config.TokenURL, strings.NewReader(v.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if mode == InHeaderMode {
		req.SetBasicAuth(url.QueryEscape(clientID), url.QueryEscape(clientSecret))
	}
	return req, nil
}
