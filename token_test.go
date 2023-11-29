package oauth2

import (
	"net/url"
	"testing"
	"time"
)

func TestTokenTypeMethod(t *testing.T) {
	testCases := []struct {
		token *Token
		want  string
	}{
		{&Token{}, "Bearer"},
		{&Token{TokenType: "beAREr"}, "Bearer"},
		{&Token{TokenType: "beAREr"}, "Bearer"},
		{&Token{TokenType: "basic"}, "Basic"},
		{&Token{TokenType: "Basic"}, "Basic"},
		{&Token{TokenType: "mac"}, "MAC"},
		{&Token{TokenType: "MAC"}, "MAC"},
		{&Token{TokenType: "mAc"}, "MAC"},
		{&Token{TokenType: "unknown"}, "unknown"},
	}

	for _, tc := range testCases {
		mustEqual(t, tc.token.Type(), tc.want)
	}
}

func TestTokenExtra(t *testing.T) {
	const wantKey = "extra-key"

	testCases := []struct {
		key   string
		value any
		want  any
	}{
		{wantKey, "abc", "abc"},
		{wantKey, 123, 123},
		{wantKey, "", ""},
		{"other-key", "def", nil},
	}

	for _, tc := range testCases {
		token := &Token{Raw: map[string]any{
			tc.key: tc.value,
		}}
		mustEqual(t, token.Extra(wantKey), tc.want)
	}
}

func TestTokenExpiry(t *testing.T) {
	now := time.Now()
	timeNow = func() time.Time { return now }
	t.Cleanup(func() { timeNow = time.Now })

	testCases := []struct {
		token *Token
		want  bool
	}{
		{&Token{Expiry: now.Add(12 * time.Second)}, false},
		{&Token{Expiry: now.Add(expiryDelta)}, false},
		{&Token{Expiry: now.Add(expiryDelta - 1*time.Nanosecond)}, true},
		{&Token{Expiry: now.Add(-1 * time.Hour)}, true},
	}

	for _, tc := range testCases {
		mustEqual(t, tc.token.IsExpired(), tc.want)
	}
}

func TestExtraValueRetrieval(t *testing.T) {
	kvmap := map[string]string{
		"scope":       "user",
		"token_type":  "bearer",
		"expires_in":  "86400.92",
		"server_time": "1443571905.5606415",
		"referer_ip":  "10.0.0.1",
		"etag":        `"afZYj912P4alikMz_P11982"`,
		"request_id":  "86400",
		"untrimmed":   "  untrimmed  ",
	}

	values := url.Values{}
	for key, value := range kvmap {
		values.Set(key, value)
	}
	tok := Token{Raw: values}

	testCases := []struct {
		key   string
		value any
	}{
		{"scope", "user"},
		{"server_time", 1443571905.5606415},
		{"referer_ip", "10.0.0.1"},
		{"expires_in", 86400.92},
		{"request_id", int64(86400)},
		{"untrimmed", "  untrimmed  "},
	}

	for _, tc := range testCases {
		mustEqual(t, tok.Extra(tc.key), tc.value)
	}
}
