package oauth2

import (
	"net/http"
	"testing"
	"time"
)

func TestWrap(t *testing.T) {
	const apikey = "Test-Api-Key-123"

	ts := newServer(func(w http.ResponseWriter, r *http.Request) {
		mustEqual(t, r.Header.Get("Authorization"), apikey)

		w.WriteHeader(http.StatusOK)
	})
	defer ts.Close()

	c := &http.Client{Timeout: 5 * time.Second}
	wc, err := Wrap("Authorization", apikey, c)
	mustOk(t, err)

	resp, err := wc.Get(ts.URL)
	mustOk(t, err)
	mustEqual(t, resp.StatusCode, http.StatusOK)
}
