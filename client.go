package oauth2

import (
	"net/http"
)

type Client struct {
	client *http.Client
	config *Config

	refreshToken string
}

func NewClient(client *http.Client, config *Config) *Client {
	c := &Client{
		client: client,
		config: config,
	}
	return c
}
