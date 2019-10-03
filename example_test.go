package oauth2_test

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/cristalhq/oauth2"
)

func ExampleConfig() {
	cfg := &oauth2.Config{
		ClientID:     "YOUR_CLIENT_ID",
		ClientSecret: "YOUR_CLIENT_SECRET",
		AuthURL:      "https://provider.com/o/oauth2/auth",
		TokenURL:     "https://provider.com/o/oauth2/token",
		Scopes:       []string{"SCOPE1", "SCOPE2"},
	}

	// Redirect user to consent page to ask for permission for the scopes specified above.
	url := cfg.AuthCodeURL("state")
	fmt.Printf("Visit the URL for the auth dialog: %v", url)

	// Use the authorization code that is pushed to the redirect
	// URL. Exchange will do the handshake to retrieve the
	// initial access token. The HTTP Client returned by
	// conf.Client will refresh the token as necessary.
	var code string
	if _, err := fmt.Scan(&code); err != nil {
		log.Fatal(err)
	}

	client := oauth2.NewClient(http.DefaultClient, cfg)

	tok, err := client.Exchange(context.Background(), code)
	if err != nil {
		log.Fatal(err)
	}

	_ = tok.AccessToken
}
