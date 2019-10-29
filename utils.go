package oauth2

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

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

func parseResponse(resp *http.Response) (*Token, error) {
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
		Raw:          vals,
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
		Raw:          make(map[string]interface{}),
	}

	_ = json.Unmarshal(body, &token.Raw) // no error checks for optional fields

	return token, nil
}
