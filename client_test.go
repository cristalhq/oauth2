package oauth2

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestExchangeRequest(t *testing.T) {
	ts := newServer(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.String() != "/token" {
			t.Errorf("Unexpected exchange request URL %q", r.URL)
		}

		headerAuth := r.Header.Get("Authorization")
		if want := "Basic Q0xJRU5UX0lEOkNMSUVOVF9TRUNSRVQ="; headerAuth != want {
			t.Errorf("Unexpected authorization header %q, want %q", headerAuth, want)
		}

		headerContentType := r.Header.Get("Content-Type")
		if headerContentType != "application/x-www-form-urlencoded" {
			t.Errorf("Unexpected Content-Type header %q", headerContentType)
		}

		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			t.Errorf("Failed reading request body: %s.", err)
		}

		if string(body) != "code=exchange-code&grant_type=authorization_code&redirect_uri=REDIRECT_URL" {
			t.Errorf("Unexpected exchange payload; got %q", body)
		}

		w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
		_, _ = w.Write([]byte("access_token=90d64460d14870c08c81352a05dedd3465940a7c&scope=user&token_type=bearer"))
	})
	defer ts.Close()

	client := newClient(ts.URL)
	tok, err := client.Exchange(context.Background(), "exchange-code")
	if err != nil {
		t.Error(err)
	}
	if !tok.Valid() {
		t.Fatalf("Token invalid. Got: %#v", tok)
	}
	if tok.AccessToken != "90d64460d14870c08c81352a05dedd3465940a7c" {
		t.Errorf("Unexpected access token, %#v.", tok.AccessToken)
	}
	if tok.TokenType != "bearer" {
		t.Errorf("Unexpected token type, %#v.", tok.TokenType)
	}
	scope := tok.Extra("scope")
	if scope != "user" {
		t.Errorf("Unexpected value for scope: %v", scope)
	}
}

func TestClientExchangeWithParams(t *testing.T) {
	ts := newServer(func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get("Authorization")

		want := "Basic Q0xJRU5UX0lEJTNGJTNGOkNMSUVOVF9TRUNSRVQlM0YlM0Y="
		if got != want {
			t.Errorf("Authorization header = %q; want %q", got, want)
		}

		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			t.Errorf("Failed reading request body: %s.", err)
		}

		want = "code=exchange-code&foo=bar&grant_type=authorization_code&redirect_uri=REDIRECT_URL"
		if string(body) != want {
			t.Errorf("got %v want %v", string(body), want)
		}

		w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
		_, _ = w.Write([]byte("access_token=90d64460d14870c08c81352a05dedd3465940a7c&scope=user&token_type=bearer"))
	})
	defer ts.Close()

	client := newClientWithConfig(Config{
		ClientID:     "CLIENT_ID??",
		ClientSecret: "CLIENT_SECRET??",
		RedirectURL:  "REDIRECT_URL",
		Scopes:       nil,
		AuthURL:      ts.URL + "/auth",
		TokenURL:     ts.URL + "/token",
	})

	_, err := client.ExchangeWithParams(context.Background(), "exchange-code", url.Values{"foo": {"bar"}})
	if err != nil {
		t.Error(err)
	}
}

func TestExchangeRequest_BadResponse(t *testing.T) {
	ts := newServer(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"scope": "user", "token_type": "bearer"}`))
	})
	defer ts.Close()

	client := newClient(ts.URL)
	_, err := client.Exchange(context.Background(), "code")
	if err == nil {
		t.Error("expected error from missing access_token")
	}
}

func TestExchangeRequest_BadResponseType(t *testing.T) {
	ts := newServer(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":123, "scope": "user", "token_type": "bearer"}`))
	})
	defer ts.Close()

	client := newClient(ts.URL)
	_, err := client.Exchange(context.Background(), "exchange-code")
	if err == nil {
		t.Error("expected error from non-string access_token")
	}
}

func TestTokenRetrieveError(t *testing.T) {
	ts := newServer(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.String() != "/token" {
			t.Errorf("Unexpected token refresh request URL, %v is found.", r.URL)
		}

		w.Header().Set("Content-type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error": "invalid_grant"}`))
	})
	defer ts.Close()

	conf := newClient(ts.URL)
	_, err := conf.Exchange(context.Background(), "exchange-code")
	if err == nil {
		t.Fatalf("got no error, expected one")
	}

	expected := fmt.Sprintf("oauth2: cannot fetch token: %v\nResponse: %s", "400 Bad Request", `{"error": "invalid_grant"}`)
	if errStr := err.Error(); errStr != expected {
		t.Fatalf("got %#v, expected %#v", errStr, expected)
	}
}

func TestRetrieveToken_InParams(t *testing.T) {
	const clientID = "client-id"
	ts := newServer(func(w http.ResponseWriter, r *http.Request) {
		got := r.FormValue("client_id")
		want := clientID
		if got != want {
			t.Errorf("client_id = %q; want %q", got, want)
		}

		got = r.FormValue("client_secret")
		want = ""
		if got != want {
			t.Errorf("client_secret = %q; want empty", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token": "ACCESS_TOKEN", "token_type": "bearer"}`)
	})
	defer ts.Close()

	client := newClientWithConfig(Config{
		ClientID:     clientID,
		ClientSecret: "",
		TokenURL:     ts.URL,
		Mode:         InParamsMode,
	})

	_, err := client.Exchange(context.Background(), "nil")
	if err != nil {
		t.Errorf("RetrieveToken = %v; want no error", err)
	}
}

func TestRetrieveToken_InHeaderMode(t *testing.T) {
	const clientID = "client-id"
	const clientSecret = "client-secret"

	ts := newServer(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok {
			t.Error("expected with HTTP Basic Authentication")
		}

		if user != clientID {
			t.Errorf("client_id = %q; want %q", user, clientID)
		}
		if pass != clientSecret {
			t.Errorf("client_secret = %q; want %q", pass, clientSecret)
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token": "ACCESS_TOKEN", "token_type": "bearer"}`)
	})
	defer ts.Close()

	client := newClientWithConfig(Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		TokenURL:     ts.URL,
		Mode:         InHeaderMode,
	})

	_, err := client.Exchange(context.Background(), "nil")
	if err != nil {
		t.Errorf("RetrieveToken = %v; want no error", err)
	}
}

func TestRetrieveToken_AutoDetect(t *testing.T) {
	const clientID = "client-id"
	const clientSecret = "client-secret"

	ts := newServer(func(w http.ResponseWriter, r *http.Request) {
		got := r.FormValue("client_id")
		want := clientID
		if got != want {
			w.WriteHeader(500)
			_, _ = io.WriteString(w, `{"access_token": "ACCESS_TOKEN", "token_type": "bearer"}`)
			return
		}

		got = r.FormValue("client_secret")
		want = clientSecret
		if got != want {
			t.Errorf("client_secret = %q; want empty", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token": "ACCESS_TOKEN", "token_type": "bearer"}`)
	})
	defer ts.Close()

	client := newClientWithConfig(Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		TokenURL:     ts.URL,
		Mode:         AutoDetectMode,
	})

	_, err := client.Exchange(context.Background(), "test")
	if err != nil {
		t.Errorf("RetrieveToken = %v; want no error", err)
	}
}

func TestExchangeRequest_WithParams(t *testing.T) {
	ts := newServer(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.String() != "/token" {
			t.Errorf("Unexpected exchange request URL, %v is found.", r.URL)
		}

		headerAuth := r.Header.Get("Authorization")
		if headerAuth != "Basic Q0xJRU5UX0lEOkNMSUVOVF9TRUNSRVQ=" {
			t.Errorf("Unexpected authorization header, %v is found.", headerAuth)
		}

		headerContentType := r.Header.Get("Content-Type")
		if headerContentType != "application/x-www-form-urlencoded" {
			t.Errorf("Unexpected Content-Type header, %v is found.", headerContentType)
		}

		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			t.Errorf("Failed reading request body: %s.", err)
		}
		if string(body) != "code=exchange-code&foo=bar&grant_type=authorization_code&redirect_uri=REDIRECT_URL" {
			t.Errorf("Unexpected exchange payload, %v is found.", string(body))
		}
		w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
		_, _ = w.Write([]byte("access_token=ProperToken&scope=user&token_type=bearer"))
	})
	defer ts.Close()

	client := newClient(ts.URL)

	tok, err := client.ExchangeWithParams(context.Background(), "exchange-code", url.Values{"foo": {"bar"}})
	if err != nil {
		t.Error(err)
	}
	if !tok.Valid() {
		t.Fatalf("Token invalid. Got: %#v", tok)
	}
	if tok.AccessToken != "ProperToken" {
		t.Errorf("Unexpected access token, %#v.", tok.AccessToken)
	}
	if tok.TokenType != "bearer" {
		t.Errorf("Unexpected token type, %#v.", tok.TokenType)
	}
	scope := tok.Extra("scope")
	if scope != "user" {
		t.Errorf("Unexpected value for scope: %v", scope)
	}
}

func TestExchangeRequest_JSONResponse(t *testing.T) {
	ts := newServer(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.String() != "/token" {
			t.Errorf("Unexpected exchange request URL, %v is found.", r.URL)
		}

		headerAuth := r.Header.Get("Authorization")
		if headerAuth != "Basic Q0xJRU5UX0lEOkNMSUVOVF9TRUNSRVQ=" {
			t.Errorf("Unexpected authorization header, %v is found.", headerAuth)
		}

		headerContentType := r.Header.Get("Content-Type")
		if headerContentType != "application/x-www-form-urlencoded" {
			t.Errorf("Unexpected Content-Type header, %v is found.", headerContentType)
		}

		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			t.Errorf("Failed reading request body: %s.", err)
		}

		if string(body) != "code=exchange-code&grant_type=authorization_code&redirect_uri=REDIRECT_URL" {
			t.Errorf("Unexpected exchange payload, %v is found.", string(body))
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token": "ProperToken", "scope": "user", "token_type": "bearer", "expires_in": 86400}`))
	})
	defer ts.Close()

	client := newClient(ts.URL)

	tok, err := client.Exchange(context.Background(), "exchange-code")
	if err != nil {
		t.Error(err)
	}

	if !tok.Valid() {
		t.Fatalf("Token invalid. Got: %#v", tok)
	}

	if tok.AccessToken != "ProperToken" {
		t.Errorf("Unexpected access token, %#v.", tok.AccessToken)
	}

	if tok.TokenType != "bearer" {
		t.Errorf("Unexpected token type, %#v.", tok.TokenType)
	}

	scope := tok.Extra("scope")
	if scope != "user" {
		t.Errorf("Unexpected value for scope: %v", scope)
	}

	expiresIn := tok.Extra("expires_in")
	if expiresIn != float64(86400) {
		t.Errorf("Unexpected non-numeric value for expires_in: %v", expiresIn)
	}
}

func TestExchangeRequest_JSONResponse_Expiry(t *testing.T) {
	seconds := int32((24 * time.Hour).Seconds())

	f := func(expires string, want, nullExpires bool) {
		t.Helper()

		testExchangeRequestJSONResponseExpiry(t, expires, want, nullExpires)
	}

	f(
		fmt.Sprintf(`"expires_in": %d`, seconds),
		true, false,
	)
	f(
		fmt.Sprintf(`"expires_in": "%d"`, seconds),
		true, false,
	)
	f(
		`"expires_in": null`,
		true, true,
	)
	f(
		`"expires_in": false`,
		false, false,
	)
	f(
		`"expires_in": {}`,
		false, false,
	)
	f(
		`"expires_in": "zzz"`,
		false, false,
	)
}

func testExchangeRequestJSONResponseExpiry(t *testing.T, exp string, want, nullExpires bool) {
	ts := newServer(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(fmt.Sprintf(`{"access_token": "90d", "scope": "user", "token_type": "bearer", %s}`, exp)))
	})
	defer ts.Close()

	const day = 24 * time.Hour
	conf := newClient(ts.URL)
	t1 := time.Now().Add(day)
	tok, err := conf.Exchange(context.Background(), "exchange-code")
	t2 := t1.Add(day)

	if got := (err == nil); got != want {
		if want {
			t.Errorf("unexpected error: got %v", err)
		} else {
			t.Errorf("unexpected success")
		}
	}
	if !want {
		return
	}
	if !tok.Valid() {
		t.Fatalf("Token invalid. Got: %#v", tok)
	}
	expiry := tok.Expiry

	if nullExpires && expiry.IsZero() {
		return
	}
	if expiry.Before(t1) || expiry.After(t2) {
		t.Errorf("Unexpected value for Expiry: %v (should be between %v and %v)", expiry, t1, t2)
	}
}

func TestPasswordCredentialsTokenRequest(t *testing.T) {
	ts := newServer(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		expected := "/token"
		if r.URL.String() != expected {
			t.Errorf("URL = %q; want %q", r.URL, expected)
		}

		headerAuth := r.Header.Get("Authorization")
		expected = "Basic Q0xJRU5UX0lEOkNMSUVOVF9TRUNSRVQ="
		if headerAuth != expected {
			t.Errorf("Authorization header = %q; want %q", headerAuth, expected)
		}

		headerContentType := r.Header.Get("Content-Type")
		expected = "application/x-www-form-urlencoded"
		if headerContentType != expected {
			t.Errorf("Content-Type header = %q; want %q", headerContentType, expected)
		}

		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			t.Errorf("Failed reading request body: %s.", err)
		}

		expected = "grant_type=password&password=password1&scope=scope1+scope2&username=user1"
		if string(body) != expected {
			t.Errorf("res.Body = %q; want %q", string(body), expected)
		}

		w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
		_, _ = w.Write([]byte("access_token=ProperToken&scope=user&token_type=bearer"))
	})
	defer ts.Close()

	client := newClient(ts.URL)
	tok, err := client.CredentialsToken(context.Background(), "user1", "password1")
	if err != nil {
		t.Error(err)
	}
	if !tok.Valid() {
		t.Fatalf("Token invalid. Got: %#v", tok)
	}

	expected := "ProperToken"
	if tok.AccessToken != expected {
		t.Errorf("AccessToken = %q; want %q", tok.AccessToken, expected)
	}

	expected = "bearer"
	if tok.TokenType != expected {
		t.Errorf("TokenType = %q; want %q", tok.TokenType, expected)
	}
}

// func TestTokenRefreshRequest(t *testing.T) {
// 	ts := newServer(func(w http.ResponseWriter, r *http.Request) {
// 		if r.URL.String() == "/somethingelse" {
// 			return
// 		}
// 		if r.URL.String() != "/token" {
// 			t.Errorf("Unexpected token refresh request URL %q", r.URL)
// 		}
// 		headerContentType := r.Header.Get("Content-Type")
// 		if headerContentType != "application/x-www-form-urlencoded" {
// 			t.Errorf("Unexpected Content-Type header %q", headerContentType)
// 		}
// 		body, _ := ioutil.ReadAll(r.Body)
// 		if string(body) != "grant_type=refresh_token&refresh_token=REFRESH_TOKEN" {
// 			t.Errorf("Unexpected refresh token payload %q", body)
// 		}
// 		w.Header().Set("Content-Type", "application/json")
// 		io.WriteString(w, `{"access_token": "foo", "refresh_token": "bar"}`)
// 	})
// 	defer ts.Close()
// 	client := newClient(ts.URL)
// 	c := client.Client(context.Background(), &Token{RefreshToken: "REFRESH_TOKEN"})
// 	c.Get(ts.URL + "/somethingelse")
// }

// func TestFetchWithNoRefreshToken(t *testing.T) {
// 	ts := newServer(func(w http.ResponseWriter, r *http.Request) {
// 		if r.URL.String() == "/somethingelse" {
// 			return
// 		}
// 		if r.URL.String() != "/token" {
// 			t.Errorf("Unexpected token refresh request URL, %v is found.", r.URL)
// 		}
// 		headerContentType := r.Header.Get("Content-Type")
// 		if headerContentType != "application/x-www-form-urlencoded" {
// 			t.Errorf("Unexpected Content-Type header, %v is found.", headerContentType)
// 		}
// 		body, _ := ioutil.ReadAll(r.Body)
// 		if string(body) != "client_id=CLIENT_ID&grant_type=refresh_token&refresh_token=REFRESH_TOKEN" {
// 			t.Errorf("Unexpected refresh token payload, %v is found.", string(body))
// 		}
// 	})
// 	defer ts.Close()

// 	conf := newClient(ts.URL)
// 	c := conf.Client(context.Background(), nil)
// 	_, err := c.Get(ts.URL + "/somethingelse")
// 	if err == nil {
// 		t.Errorf("Fetch should return an error if no refresh token is set")
// 	}
// }

// func TestRefreshToken_RefreshTokenReplacement(t *testing.T) {
// 	ts := newServer(func(w http.ResponseWriter, r *http.Request) {
// 		w.Header().Set("Content-Type", "application/json")
// 		w.Write([]byte(`{"access_token":"ACCESS_TOKEN",  "scope": "user", "token_type": "bearer", "refresh_token": "NEW_REFRESH_TOKEN"}`))
// 		return
// 	})
// 	defer ts.Close()
// 	conf := newConf(ts.URL)
// 	tkr := conf.TokenSource(context.Background(), &Token{RefreshToken: "OLD_REFRESH_TOKEN"})
// 	tk, err := tkr.Token()
// 	if err != nil {
// 		t.Errorf("got err = %v; want none", err)
// 		return
// 	}
// 	if want := "NEW_REFRESH_TOKEN"; tk.RefreshToken != want {
// 		t.Errorf("RefreshToken = %q; want %q", tk.RefreshToken, want)
// 	}
// }

// func TestRefreshToken_RefreshTokenPreservation(t *testing.T) {
// 	ts := newServer(func(w http.ResponseWriter, r *http.Request) {
// 		w.Header().Set("Content-Type", "application/json")
// 		w.Write([]byte(`{"access_token":"ACCESS_TOKEN",  "scope": "user", "token_type": "bearer"}`))
// 		return
// 	})
// 	defer ts.Close()
// 	conf := newConf(ts.URL)
// 	const oldRefreshToken = "OLD_REFRESH_TOKEN"
// 	tkr := conf.TokenSource(context.Background(), &Token{RefreshToken: oldRefreshToken})
// 	tk, err := tkr.Token()
// 	if err != nil {
// 		t.Fatalf("got err = %v; want none", err)
// 	}
// 	if tk.RefreshToken != oldRefreshToken {
// 		t.Errorf("RefreshToken = %q; want %q", tk.RefreshToken, oldRefreshToken)
// 	}
// }

// func TestConfigClientWithToken(t *testing.T) {
// 	tok := &Token{
// 		AccessToken: "abc123",
// 	}
// 	ts := newServer(func(w http.ResponseWriter, r *http.Request) {
// 		if got, want := r.Header.Get("Authorization"), fmt.Sprintf("Bearer %s", tok.AccessToken); got != want {
// 			t.Errorf("Authorization header = %q; want %q", got, want)
// 		}
// 		return
// 	})
// 	defer ts.Close()
// 	conf := newConf(ts.URL)

// 	c := conf.Client(context.Background(), tok)
// 	req, err := http.NewRequest("GET", ts.URL, nil)
// 	if err != nil {
// 		t.Error(err)
// 	}
// 	_, err = c.Do(req)
// 	if err != nil {
// 		t.Error(err)
// 	}
// }

func TestRetrieveTokenWithContexts(t *testing.T) {
	const clientID = "client-id"

	ts := newServer(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token": "ACCESS_TOKEN", "token_type": "bearer"}`)
	})
	defer ts.Close()

	client := newClientWithConfig(Config{
		ClientID:     clientID,
		ClientSecret: "",
		TokenURL:     ts.URL,
		Mode:         AutoDetectMode,
	})
	_, err := client.retrieveToken(context.Background(), url.Values{})
	if err != nil {
		t.Errorf("RetrieveToken (with background context) = %v; want no error", err)
	}

	retrieved := make(chan struct{})
	cancellingts := newServer(func(w http.ResponseWriter, r *http.Request) {
		<-retrieved
	})
	defer cancellingts.Close()

	client = newClientWithConfig(Config{
		ClientID:     clientID,
		ClientSecret: "",
		TokenURL:     ts.URL,
		Mode:         InParamsMode,
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = client.retrieveToken(ctx, url.Values{})
	close(retrieved)
	if err == nil {
		t.Errorf("RetrieveToken (with cancelled context) = nil; want error")
	}
}

func newClient(url string) *Client {
	cfg := Config{
		ClientID:     "CLIENT_ID",
		ClientSecret: "CLIENT_SECRET",
		AuthURL:      url + "/auth",
		TokenURL:     url + "/token",
		Mode:         AutoDetectMode,
		RedirectURL:  "REDIRECT_URL",
		Scopes:       []string{"scope1", "scope2"},
	}
	return NewClient(http.DefaultClient, cfg)
}

func newClientWithConfig(cfg Config) *Client {
	return NewClient(http.DefaultClient, cfg)
}

func newServer(h func(w http.ResponseWriter, r *http.Request)) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(h))
}
