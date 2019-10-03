package oauth2

import (
	"net/url"
	"testing"
	"time"
)

func TestTokenTypeMethod(t *testing.T) {
	f := func(token *Token, want string) {
		got := token.Type()
		if got != want {
			t.Errorf("got %v; want %v", got, want)
		}
	}

	f(
		&Token{}, "Bearer",
	)
	f(
		&Token{TokenType: "beAREr"}, "Bearer",
	)
	f(
		&Token{TokenType: "beAREr"}, "Bearer",
	)
	f(
		&Token{TokenType: "basic"}, "Basic",
	)
	f(
		&Token{TokenType: "Basic"}, "Basic",
	)
	f(
		&Token{TokenType: "mac"}, "MAC",
	)
	f(
		&Token{TokenType: "MAC"}, "MAC",
	)
	f(
		&Token{TokenType: "mAc"}, "MAC",
	)
	f(
		&Token{TokenType: "unknown"}, "unknown",
	)
}

func TestTokenExtra(t *testing.T) {
	const wantKey = "extra-key"

	f := func(key string, value, want interface{}) {
		extra := map[string]interface{}{
			key: value,
		}
		token := &Token{
			raw: extra,
		}

		got := token.Extra(wantKey)
		if got != want {
			t.Errorf("Extra(%q) = %q; want %q", key, got, want)
		}
	}

	f("extra-key", "abc", "abc")
	f("extra-key", 123, 123)
	f("extra-key", "", "")
	f("other-key", "def", nil)
}

func TestTokenExpiry(t *testing.T) {
	now := time.Now()
	timeNow = func() time.Time { return now }
	defer func() { timeNow = time.Now }()

	f := func(token *Token, want bool) {
		got := token.IsExpired()
		if got != want {
			t.Errorf("got %v; want %v", got, want)
		}
	}

	f(
		&Token{Expiry: now.Add(12 * time.Second)},
		false,
	)
	f(
		&Token{Expiry: now.Add(expiryDelta)},
		false,
	)
	f(
		&Token{Expiry: now.Add(expiryDelta - 1*time.Nanosecond)},
		true,
	)
	f(
		&Token{Expiry: now.Add(-1 * time.Hour)},
		true,
	)
}

func TestExtraValueRetrieval(t *testing.T) {
	kvmap := map[string]string{
		"scope":       "user",
		"token_type":  "bearer",
		"expires_in":  "86400.92",
		"server_time": "1443571905.5606415",
		"referer_ip":  "10.0.0.1",
		"etag":        "\"afZYj912P4alikMz_P11982\"",
		"request_id":  "86400",
		"untrimmed":   "  untrimmed  ",
	}
	values := url.Values{}
	for key, value := range kvmap {
		values.Set(key, value)
	}

	tok := Token{raw: values}

	f := func(key string, want interface{}) {
		value := tok.Extra(key)
		if value != want {
			t.Errorf("got %q; want %q", value, want)
		}
	}

	f("scope", "user")
	f("server_time", 1443571905.5606415)
	f("referer_ip", "10.0.0.1")
	f("expires_in", 86400.92)
	f("request_id", int64(86400))
	f("untrimmed", "  untrimmed  ")
}
