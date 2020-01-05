package oauth2

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

// Client represents an OAuth2 HTTP client.
//
type Client struct {
	client *http.Client
	config *Config

	refreshToken string
}

// NewClient instantiates a new client with a given config.
//
func NewClient(client *http.Client, config *Config) *Client {
	c := &Client{
		client: client,
		config: config,
	}
	return c
}

// Exchange converts an authorization code into an OAuth2 token.
//
func (c *Client) Exchange(ctx context.Context, code string) (*Token, error) {
	return c.ExchangeWithParams(ctx, code, nil)
}

// ExchangeWithParams converts an authorization code into an OAuth2 token.
//
func (c *Client) ExchangeWithParams(ctx context.Context, code string, params url.Values) (*Token, error) {
	vals := cloneURLValues(params)
	vals.Add("grant_type", "authorization_code")
	vals.Add("code", code)

	if c.config.RedirectURL != "" {
		vals.Set("redirect_uri", c.config.RedirectURL)
	}
	return c.retrieveToken(ctx, vals)
}

// CredentialsToken retrieves a token for given username and password.
//
func (c *Client) CredentialsToken(ctx context.Context, username, password string) (*Token, error) {
	v := url.Values{
		"grant_type": []string{"password"},
		"username":   []string{username},
		"password":   []string{password},
	}

	if len(c.config.Scopes) > 0 {
		v.Set("scope", strings.Join(c.config.Scopes, " "))
	}
	return c.retrieveToken(ctx, v)
}

// Token renews a token based on previous token.
//
// WARNING: It's not safe for concurrent usage.
//
func (c *Client) Token(ctx context.Context) (*Token, error) {
	if c.refreshToken == "" {
		return nil, errors.New("oauth2: token expired and refresh token is not set")
	}

	v := url.Values{
		"grant_type":    []string{"refresh_token"},
		"refresh_token": []string{c.refreshToken},
	}

	token, err := c.retrieveToken(ctx, v)
	if err != nil {
		return nil, err
	}

	if c.refreshToken != token.RefreshToken {
		c.refreshToken = token.RefreshToken
	}
	return token, nil
}

func (c *Client) retrieveToken(ctx context.Context, vals url.Values) (*Token, error) {
	mode := c.config.Mode

	shouldGuessAuthMode := mode == AutoDetectMode
	if shouldGuessAuthMode {
		mode = InHeaderMode
	}

	req, err := c.newTokenRequest(mode, vals)
	if err != nil {
		return nil, err
	}

	resp, err := c.sendRequest(ctx, req)
	if err != nil {
		if !shouldGuessAuthMode {
			return nil, err
		}
		mode = InParamsMode

		var err error
		req, err = c.newTokenRequest(mode, vals)
		if err != nil {
			return nil, err
		}

		resp, err = c.sendRequest(ctx, req)
		if err != nil {
			return nil, err
		}
		c.config.Mode = mode
	}
	return parseResponse(resp)
}

func (c *Client) sendRequest(ctx context.Context, req *http.Request) (*http.Response, error) {
	return c.client.Do(req.WithContext(ctx))
}

func (c *Client) newTokenRequest(mode Mode, v url.Values) (*http.Request, error) {
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

	req, err := http.NewRequest("POST", c.config.TokenURL, strings.NewReader(v.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if mode == InHeaderMode {
		req.SetBasicAuth(url.QueryEscape(clientID), url.QueryEscape(clientSecret))
	}
	return req, nil
}
