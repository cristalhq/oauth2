package oauth2

import (
	"net/http"
	"net/url"
	"reflect"
	"testing"
)

func TestAuthCodeURL(t *testing.T) {
	testCases := []struct {
		cfg   Config
		state string
		want  string
	}{
		{
			Config{
				ClientID:     "CLIENT_ID",
				ClientSecret: "CLIENT_SECRET",
				RedirectURL:  "REDIRECT_URL",
				Scopes:       nil,
				AuthURL:      "server:1234/auth",
				TokenURL:     "",
			},
			"test-state",
			`server:1234/auth?client_id=CLIENT_ID&redirect_uri=REDIRECT_URL&response_type=code&state=test-state`,
		},
		{
			Config{
				ClientID:     "CLIENT_ID",
				ClientSecret: "CLIENT_SECRET",
				RedirectURL:  "REDIRECT_URL",
				Scopes:       nil,
				AuthURL:      "server:1234/auth?foo=bar",
				TokenURL:     "",
			},
			"test-state",
			`server:1234/auth?foo=bar&client_id=CLIENT_ID&redirect_uri=REDIRECT_URL&response_type=code&state=test-state`,
		},
		{
			Config{
				ClientID:     "CLIENT_ID",
				ClientSecret: "CLIENT_SECRET",
				RedirectURL:  "REDIRECT_URL",
				Scopes:       []string{"scope1", "scope2"},
				AuthURL:      "server:1234/auth",
				TokenURL:     "",
			},
			"test-state",
			`server:1234/auth?client_id=CLIENT_ID&redirect_uri=REDIRECT_URL&response_type=code&scope=scope1+scope2&state=test-state`,
		},
		{
			Config{
				ClientID: "CLIENT_ID",
				AuthURL:  "server:1234/auth-url",
				TokenURL: "",
			},
			"",
			`server:1234/auth-url?client_id=CLIENT_ID&response_type=code`,
		},
	}

	for _, tc := range testCases {
		client := NewClient(http.DefaultClient, tc.cfg)
		url := client.AuthCodeURL(tc.state)
		mustEqual(t, url, tc.want)
	}
}

func TestAuthCodeURLWithParams(t *testing.T) {
	testCases := []struct {
		cfg    Config
		state  string
		params url.Values
		want   string
	}{
		{
			Config{
				ClientID:     "CLIENT_ID",
				ClientSecret: "CLIENT_SECRET",
				RedirectURL:  "REDIRECT_URL",
				Scopes:       nil,
				AuthURL:      "server:1234/auth",
				TokenURL:     "",
			},
			"test-state",
			nil,
			`server:1234/auth?client_id=CLIENT_ID&redirect_uri=REDIRECT_URL&response_type=code&state=test-state`,
		},
		{
			Config{
				ClientID:     "CLIENT_ID",
				ClientSecret: "CLIENT_SECRET",
				RedirectURL:  "REDIRECT_URL",
				Scopes:       nil,
				AuthURL:      "server:1234/auth?foo=bar",
				TokenURL:     "",
			},
			"test-state",
			nil,
			`server:1234/auth?foo=bar&client_id=CLIENT_ID&redirect_uri=REDIRECT_URL&response_type=code&state=test-state`,
		},
		{
			Config{
				ClientID:     "CLIENT_ID",
				ClientSecret: "CLIENT_SECRET",
				RedirectURL:  "REDIRECT_URL",
				Scopes:       []string{"scope1", "scope2"},
				AuthURL:      "server:1234/auth",
				TokenURL:     "",
			},
			"test-state",
			url.Values{
				"access_type": []string{"anything"},
				"param1":      []string{"value1"},
			},
			`server:1234/auth?access_type=anything&client_id=CLIENT_ID&param1=value1&redirect_uri=REDIRECT_URL&response_type=code&scope=scope1+scope2&state=test-state`,
		},
		{
			Config{
				ClientID: "CLIENT_ID",
				AuthURL:  "server:1234/auth-url",
				TokenURL: "",
			},
			"",
			nil,
			`server:1234/auth-url?client_id=CLIENT_ID&response_type=code`,
		},
	}

	for _, tc := range testCases {
		client := NewClient(http.DefaultClient, tc.cfg)
		url := client.AuthCodeURLWithParams(tc.state, tc.params)
		mustEqual(t, url, tc.want)
	}
}

func mustOk(tb testing.TB, err error) {
	tb.Helper()
	if err != nil {
		tb.Fatal(err)
	}
}

func mustFail(tb testing.TB, err error) {
	tb.Helper()
	if err == nil {
		tb.Fatal()
	}
}

func mustEqual[T any](tb testing.TB, have, want T) {
	tb.Helper()
	if !reflect.DeepEqual(have, want) {
		tb.Fatalf("\nhave: %+v\nwant: %+v\n", have, want)
	}
}
