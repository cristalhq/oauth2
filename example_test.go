package oauth2_test

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/cristalhq/oauth2"
)

func Example() {
	config := oauth2.Config{
		ClientID:     "YOUR_CLIENT_ID",
		ClientSecret: "YOUR_CLIENT_SECRET",
		AuthURL:      "https://example.com/o/oauth2/auth",
		TokenURL:     "https://example.com/o/oauth2/token",
		Scopes:       []string{"email", "avatar"},
	}

	// create a client
	client := oauth2.NewClient(http.DefaultClient, config)

	// url to fetch the code
	url := client.AuthCodeURL("state")
	fmt.Printf("Visit the URL for the auth dialog: %v", url)

	// Use the authorization code that is pushed to the redirect URL.
	// Exchange will do the handshake to retrieve the initial access token.
	var code string
	if _, err := fmt.Scan(&code); err != nil {
		log.Fatal(err)
	}

	// get a token
	token, err := client.Exchange(context.Background(), code)
	if err != nil {
		panic(err)
	}

	var _ string = token.AccessToken  // OAuth2 token
	var _ string = token.TokenType    // type of the token
	var _ string = token.RefreshToken // token for a refresh
	var _ time.Time = token.Expiry    // token expiration time
	var _ bool = token.IsExpired()    // have token expired?
}
