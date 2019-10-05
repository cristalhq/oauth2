package oauth2

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
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
	v := url.Values{
		"grant_type": []string{"authorization_code"},
		"code":       []string{code},
	}

	if c.config.RedirectURL != "" {
		v.Set("redirect_uri", c.config.RedirectURL)
	}
	return c.retrieveToken(ctx, v)
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

func (c *Client) retrieveToken(ctx context.Context, v url.Values) (*Token, error) {
	req, err := newTokenRequest(c.config.TokenURL, c.config.ClientID, c.config.ClientSecret, v, c.config.Mode)
	if err != nil {
		return nil, err
	}

	token, err := c.sendRequest(ctx, req)
	if err != nil {
		return nil, err
	}
	return token, nil
}

func (c *Client) sendRequest(ctx context.Context, req *http.Request) (*Token, error) {
	resp, err := c.client.Do(req.WithContext(ctx))
	if err != nil {
		return nil, err
	}

	body, err := ioutil.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()

	if err != nil {
		return nil, fmt.Errorf("oauth2: cannot fetch token: %v", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("oauth2: cannot fetch token: %v %v\nResponse: %s",
			resp.StatusCode, http.StatusText(resp.StatusCode), string(body))
	}

	var token *Token

	switch responseContentType(resp) {
	case "text/plain", "application/x-www-form-urlencoded":
		token, err = parseText(body)
	default:
		token, err = parseJSON(body)
	}

	switch {
	case err != nil:
		return nil, err
	case token.AccessToken == "":
		return nil, errors.New("oauth2: server response missing access_token")
	default:
		return token, nil
	}
}

func responseContentType(resp *http.Response) string {
	content, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	return content
}

func parseText(body []byte) (*Token, error) {
	vals, err := url.ParseQuery(string(body))
	if err != nil {
		return nil, err
	}

	token := &Token{
		AccessToken:  vals.Get("access_token"),
		TokenType:    vals.Get("token_type"),
		RefreshToken: vals.Get("refresh_token"),
		raw:          vals,
	}

	e := vals.Get("expires_in")
	expires, _ := strconv.Atoi(e)
	if expires != 0 {
		token.Expiry = time.Now().Add(time.Duration(expires) * time.Second)
	}
	return token, nil
}

func parseJSON(body []byte) (*Token, error) {
	var tj tokenJSON
	if err := json.Unmarshal(body, &tj); err != nil {
		return nil, err
	}

	token := &Token{
		AccessToken:  tj.AccessToken,
		TokenType:    tj.TokenType,
		RefreshToken: tj.RefreshToken,
		Expiry:       tj.expiry(),
		raw:          make(map[string]interface{}),
	}

	_ = json.Unmarshal(body, &token.raw) // no error checks for optional fields

	return token, nil
}

// newTokenRequest returns a new *http.Request to retrieve a new token
// from tokenURL using the provided clientID, clientSecret, and POST body parameters.
//
// inParams is whether the clientID & clientSecret should be encoded
// as the POST body. An 'inParams' value of true means to send it in
// the POST body (along with any values in v); false means to send it
// in the Authorization header.
func newTokenRequest(tokenURL, clientID, clientSecret string, v url.Values, mode Mode) (*http.Request, error) {
	modeStyleProbe := mode == ModeAutoDetect
	if modeStyleProbe {
		mode = ModeInHeader
	}

	if mode == ModeInParams {
		v = cloneURLValues(v)
		if clientID != "" {
			v.Set("client_id", clientID)
		}
		if clientSecret != "" {
			v.Set("client_secret", clientSecret)
		}
	}

	req, err := http.NewRequest("POST", tokenURL, strings.NewReader(v.Encode()))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if mode == ModeInHeader {
		req.SetBasicAuth(url.QueryEscape(clientID), url.QueryEscape(clientSecret))
	}
	return req, nil
}

func cloneURLValues(vals url.Values) url.Values {
	if vals == nil {
		return url.Values{}
	}

	v2 := make(url.Values, len(vals))
	for k, v := range vals {
		v2[k] = append([]string(nil), v...)
	}
	return v2
}
