package oauth2

import (
	"net/http"
	"testing"
	"time"
)

func TestWrap(t *testing.T) {
	apikey := "Test-Api-Key-123"

	ts := newServer(func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get("Authorization")
		want := apikey
		if got != want {
			t.Errorf("Authorization header = %q; want %q", got, want)
		}
		w.WriteHeader(http.StatusOK)
	})
	defer ts.Close()

	c := &http.Client{Timeout: 5 * time.Second}
	wc, err := Wrap("Authorization", apikey, c)

	if err != nil {
		t.Fatal(err)
	}
	resp, err := wc.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status code %#v, want %#v", resp.StatusCode, http.StatusOK)
	}
}
