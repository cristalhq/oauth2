package oauth2

import (
	"net/url"
	"testing"
)

func TestAuthCodeURL(t *testing.T) {
	f := func(cfg *Config, state string, params url.Values, want string) {
		url := cfg.AuthCodeURLWithParams(state, params)
		if url != want {
			t.Errorf("got %q; want %q", url, want)
		}
	}

	f(
		&Config{
			ClientID:     "CLIENT_ID",
			ClientSecret: "CLIENT_SECRET",
			RedirectURL:  "REDIRECT_URL",
			Scopes:       nil,
			AuthURL:      "server:1234/auth",
			TokenURL:     "server:1234/token",
		},
		"test-state",
		nil,
		`server:1234/auth?client_id=CLIENT_ID&redirect_uri=REDIRECT_URL&response_type=code&state=test-state`,
	)

	f(
		&Config{
			ClientID:     "CLIENT_ID",
			ClientSecret: "CLIENT_SECRET",
			RedirectURL:  "REDIRECT_URL",
			Scopes:       []string{"scope1", "scope2"},
			AuthURL:      "server:1234/auth",
			TokenURL:     "server:1234/token",
		},
		"test-state",
		url.Values{
			"access_type": []string{"offline"},
			"prompt":      []string{"consent"},
		},
		`server:1234/auth?access_type=offline&client_id=CLIENT_ID&prompt=consent&redirect_uri=REDIRECT_URL&response_type=code&scope=scope1+scope2&state=test-state`,
	)

	f(
		&Config{
			ClientID: "CLIENT_ID",
			AuthURL:  "server:1234/auth-url",
			TokenURL: "server:1234/token-url",
		},
		"",
		nil,
		`server:1234/auth-url?client_id=CLIENT_ID&response_type=code`,
	)
}
