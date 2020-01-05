package oauth2

import (
	"net/url"
	"testing"
)

func TestAuthCodeURL(t *testing.T) {
	f := func(cfg *Config, state string, want string) {
		t.Helper()

		url := cfg.AuthCodeURL(state)
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
		`server:1234/auth?client_id=CLIENT_ID&redirect_uri=REDIRECT_URL&response_type=code&state=test-state`,
	)

	f(
		&Config{
			ClientID:     "CLIENT_ID",
			ClientSecret: "CLIENT_SECRET",
			RedirectURL:  "REDIRECT_URL",
			Scopes:       nil,
			AuthURL:      "server:1234/auth?foo=bar",
			TokenURL:     "server:1234/token",
		},
		"test-state",
		`server:1234/auth?foo=bar&client_id=CLIENT_ID&redirect_uri=REDIRECT_URL&response_type=code&state=test-state`,
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
		`server:1234/auth?client_id=CLIENT_ID&redirect_uri=REDIRECT_URL&response_type=code&scope=scope1+scope2&state=test-state`,
	)

	f(
		&Config{
			ClientID: "CLIENT_ID",
			AuthURL:  "server:1234/auth-url",
			TokenURL: "server:1234/token-url",
		},
		"",
		`server:1234/auth-url?client_id=CLIENT_ID&response_type=code`,
	)
}

func AuthCodeURLWithParams(t *testing.T) {
	f := func(cfg *Config, state string, params url.Values, want string) {
		t.Helper()

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
			Scopes:       nil,
			AuthURL:      "server:1234/auth?foo=bar",
			TokenURL:     "server:1234/token",
		},
		"test-state",
		nil,
		`server:1234/auth?foo=bar&client_id=CLIENT_ID&redirect_uri=REDIRECT_URL&response_type=code&state=test-state`,
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
			"access_type": []string{"anything"},
			"param1":      []string{"value1"},
		},
		`server:1234/auth?access_type=anything&client_id=CLIENT_ID&param1=value1&redirect_uri=REDIRECT_URL&response_type=code&scope=scope1+scope2&state=test-state`,
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
