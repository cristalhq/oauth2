package oauth2

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestExchangeRequest(t *testing.T) {
	ts := newServer(func(w http.ResponseWriter, r *http.Request) {
		mustEqual(t, r.URL.String(), "/token")

		headerAuth := r.Header.Get("Authorization")
		mustEqual(t, headerAuth, "Basic Q0xJRU5UX0lEOkNMSUVOVF9TRUNSRVQ=")

		headerContentType := r.Header.Get("Content-Type")
		mustEqual(t, headerContentType, "application/x-www-form-urlencoded")

		body, err := io.ReadAll(r.Body)
		mustOk(t, err)
		mustEqual(t, string(body), "code=exchange-code&grant_type=authorization_code&redirect_uri=REDIRECT_URL")

		w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
		fmt.Fprint(w, "access_token=90d64460d14870c08c81352a05dedd3465940a7c&scope=user&token_type=bearer")
	})
	defer ts.Close()

	client := newClient(ts.URL)
	tok, err := client.Exchange(context.Background(), "exchange-code")
	mustOk(t, err)
	mustEqual(t, tok.Valid(), true)
	mustEqual(t, tok.AccessToken, "90d64460d14870c08c81352a05dedd3465940a7c")
	mustEqual(t, tok.TokenType, "bearer")
	mustEqual(t, tok.Extra("scope"), "user")
}

func TestClientExchangeWithParams(t *testing.T) {
	ts := newServer(func(w http.ResponseWriter, r *http.Request) {
		headerAuth := r.Header.Get("Authorization")
		mustEqual(t, headerAuth, "Basic Q0xJRU5UX0lEJTNGJTNGOkNMSUVOVF9TRUNSRVQlM0YlM0Y=")

		body, err := io.ReadAll(r.Body)
		mustOk(t, err)
		mustEqual(t, string(body), "code=exchange-code&foo=bar&grant_type=authorization_code&redirect_uri=REDIRECT_URL")

		w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
		fmt.Fprint(w, "access_token=90d64460d14870c08c81352a05dedd3465940a7c&scope=user&token_type=bearer")
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

	_, err := client.ExchangeWithParams(
		context.Background(),
		"exchange-code",
		url.Values{"foo": {"bar"}},
	)
	mustOk(t, err)
}

func TestExchangeRequest_BadResponse(t *testing.T) {
	ts := newServer(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"scope": "user", "token_type": "bearer"}`)
	})
	defer ts.Close()

	client := newClient(ts.URL)
	_, err := client.Exchange(context.Background(), "code")
	mustFail(t, err)
}

func TestExchangeRequest_BadResponseType(t *testing.T) {
	ts := newServer(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"access_token":123, "scope": "user", "token_type": "bearer"}`)
	})
	defer ts.Close()

	client := newClient(ts.URL)
	_, err := client.Exchange(context.Background(), "exchange-code")
	mustFail(t, err)
}

func TestTokenRetrieveError(t *testing.T) {
	ts := newServer(func(w http.ResponseWriter, r *http.Request) {
		mustEqual(t, r.URL.String(), "/token")

		w.Header().Set("Content-type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"error": "invalid_grant"}`)
	})
	defer ts.Close()

	conf := newClient(ts.URL)
	_, err := conf.Exchange(context.Background(), "exchange-code")
	mustFail(t, err)

	expected := fmt.Sprintf("oauth2: cannot fetch token: %v\nResponse: %s", "400 Bad Request", `{"error": "invalid_grant"}`)
	mustEqual(t, err.Error(), expected)
}

func TestRetrieveToken_InParams(t *testing.T) {
	const clientID = "client-id"
	ts := newServer(func(w http.ResponseWriter, r *http.Request) {
		mustEqual(t, r.FormValue("client_id"), clientID)
		mustEqual(t, r.FormValue("client_secret"), "")

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"access_token": "ACCESS_TOKEN", "token_type": "bearer"}`)
	})
	defer ts.Close()

	client := newClientWithConfig(Config{
		ClientID:     clientID,
		ClientSecret: "",
		TokenURL:     ts.URL,
		Mode:         InParamsMode,
	})

	_, err := client.Exchange(context.Background(), "nil")
	mustOk(t, err)
}

func TestRetrieveToken_InHeaderMode(t *testing.T) {
	const clientID = "client-id"
	const clientSecret = "client-secret"

	ts := newServer(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		mustEqual(t, ok, true)
		mustEqual(t, user, clientID)
		mustEqual(t, pass, clientSecret)

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"access_token": "ACCESS_TOKEN", "token_type": "bearer"}`)
	})
	defer ts.Close()

	client := newClientWithConfig(Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		TokenURL:     ts.URL,
		Mode:         InHeaderMode,
	})

	_, err := client.Exchange(context.Background(), "nil")
	mustOk(t, err)
}

func TestRetrieveToken_AutoDetect(t *testing.T) {
	const clientID = "client-id"
	const clientSecret = "client-secret"

	ts := newServer(func(w http.ResponseWriter, r *http.Request) {
		if r.FormValue("client_id") != clientID {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, `{"access_token": "ACCESS_TOKEN", "token_type": "bearer"}`)
			return
		}

		mustEqual(t, r.FormValue("client_secret"), clientSecret)

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"access_token": "ACCESS_TOKEN", "token_type": "bearer"}`)
	})
	defer ts.Close()

	client := newClientWithConfig(Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		TokenURL:     ts.URL,
		Mode:         AutoDetectMode,
	})

	_, err := client.Exchange(context.Background(), "test")
	mustOk(t, err)
}

func TestExchangeRequest_WithParams(t *testing.T) {
	ts := newServer(func(w http.ResponseWriter, r *http.Request) {
		mustEqual(t, r.URL.String(), "/token")

		headerAuth := r.Header.Get("Authorization")
		mustEqual(t, headerAuth, "Basic Q0xJRU5UX0lEOkNMSUVOVF9TRUNSRVQ=")

		headerContentType := r.Header.Get("Content-Type")
		mustEqual(t, headerContentType, "application/x-www-form-urlencoded")

		body, err := io.ReadAll(r.Body)
		mustOk(t, err)
		mustEqual(t, string(body), "code=exchange-code&foo=bar&grant_type=authorization_code&redirect_uri=REDIRECT_URL")

		w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
		fmt.Fprint(w, "access_token=ProperToken&scope=user&token_type=bearer")
	})
	defer ts.Close()

	client := newClient(ts.URL)

	tok, err := client.ExchangeWithParams(context.Background(), "exchange-code", url.Values{"foo": {"bar"}})
	mustOk(t, err)
	mustEqual(t, tok.Valid(), true)
	mustEqual(t, tok.AccessToken, "ProperToken")
	mustEqual(t, tok.TokenType, "bearer")
	mustEqual(t, tok.Extra("scope"), "user")
}

func TestExchangeRequest_JSONResponse(t *testing.T) {
	ts := newServer(func(w http.ResponseWriter, r *http.Request) {
		mustEqual(t, r.URL.String(), "/token")

		headerAuth := r.Header.Get("Authorization")
		mustEqual(t, headerAuth, "Basic Q0xJRU5UX0lEOkNMSUVOVF9TRUNSRVQ=")

		headerContentType := r.Header.Get("Content-Type")
		mustEqual(t, headerContentType, "application/x-www-form-urlencoded")

		body, err := io.ReadAll(r.Body)
		mustOk(t, err)
		mustEqual(t, string(body), "code=exchange-code&grant_type=authorization_code&redirect_uri=REDIRECT_URL")

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"access_token": "ProperToken", "scope": "user", "token_type": "bearer", "expires_in": 86400}`)
	})
	defer ts.Close()

	client := newClient(ts.URL)

	tok, err := client.Exchange(context.Background(), "exchange-code")
	mustOk(t, err)
	mustEqual(t, tok.Valid(), true)
	mustEqual(t, tok.AccessToken, "ProperToken")
	mustEqual(t, tok.TokenType, "bearer")
	mustEqual(t, tok.Extra("scope"), "user")
	mustEqual(t, tok.Extra("expires_in").(float64), float64(86400))
}

func TestExchangeRequest_JSONResponse_Expiry(t *testing.T) {
	testCases := []struct {
		expires     string
		want        bool
		nullExpires bool
	}{
		{`"expires_in": 86400`, true, false},
		{`"expires_in": "86400"`, true, false},
		{`"expires_in": null`, true, true},
		{`"expires_in": false`, false, false},
		{`"expires_in": {}`, false, false},
		{`"expires_in": "zzz"`, false, false},
	}

	for _, tc := range testCases {
		testExchangeRequestJSONResponseExpiry(t, tc.expires, tc.want, tc.nullExpires)
	}
}

func testExchangeRequestJSONResponseExpiry(t *testing.T, exp string, want, nullExpires bool) {
	ts := newServer(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token": "90d", "scope": "user", "token_type": "bearer", %s}`, exp)
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
	mustEqual(t, tok.Valid(), true)
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
		mustEqual(t, r.URL.String(), "/token")

		headerAuth := r.Header.Get("Authorization")
		mustEqual(t, headerAuth, "Basic Q0xJRU5UX0lEOkNMSUVOVF9TRUNSRVQ=")

		headerContentType := r.Header.Get("Content-Type")
		mustEqual(t, headerContentType, "application/x-www-form-urlencoded")

		body, err := io.ReadAll(r.Body)
		mustOk(t, err)
		mustEqual(t, string(body), "grant_type=password&password=password1&scope=scope1+scope2&username=user1")

		w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
		fmt.Fprint(w, "access_token=ProperToken&scope=user&token_type=bearer")
	})
	defer ts.Close()

	client := newClient(ts.URL)
	tok, err := client.CredentialsToken(context.Background(), "user1", "password1")
	mustOk(t, err)
	mustEqual(t, tok.Valid(), true)
	mustEqual(t, tok.AccessToken, "ProperToken")
	mustEqual(t, tok.TokenType, "bearer")
}

// func TestTokenRefreshRequest(t *testing.T) {
// 	ts := newServer(func(w http.ResponseWriter, r *http.Request) {
// 		if r.URL.String() == "/somethingelse" {
// 			return
// 		}
// 				mustEqual(t, r.URL.String(), "/token")
// 		headerContentType := r.Header.Get("Content-Type")
// 		if headerContentType != "application/x-www-form-urlencoded" {
// 			t.Errorf("Unexpected Content-Type header %q", headerContentType)
// 		}
// 		body, _ := io.ReadAll(r.Body)
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
// 				mustEqual(t, r.URL.String(), "/token")
// 		headerContentType := r.Header.Get("Content-Type")
// 		if headerContentType != "application/x-www-form-urlencoded" {
// 			t.Errorf("Unexpected Content-Type header, %v is found.", headerContentType)
// 		}
// 		body, _ := io.ReadAll(r.Body)
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
// 	mustOk(t, err)
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
// 	mustOk(t, err)
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
// 	mustOk(t, err)
// 	_, err = c.Do(req)
// 	mustOk(t, err)
// }

func TestRetrieveTokenWithContexts(t *testing.T) {
	const clientID = "client-id"

	ts := newServer(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"access_token": "ACCESS_TOKEN", "token_type": "bearer"}`)
	})
	defer ts.Close()

	client := newClientWithConfig(Config{
		ClientID:     clientID,
		ClientSecret: "",
		TokenURL:     ts.URL,
		Mode:         AutoDetectMode,
	})
	_, err := client.retrieveToken(context.Background(), url.Values{})
	mustOk(t, err)

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
	mustFail(t, err)
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
