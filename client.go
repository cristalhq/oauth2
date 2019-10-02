package oauth2

import (
	"net/http"
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
func (c *Client) retrieveToken(ctx context.Context, v url.Values) (*Token, error) {
	return nil, nil
}
