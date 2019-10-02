package oauth2

// Config describes a 3-legged OAuth2 flow.
type Config struct {
	// ClientID is the application's ID.
	ClientID string

	// ClientSecret is the application's secret.
	ClientSecret string

	// AuthURL is a URL for authentication.
	AuthURL string

	// TokenURL is a URL for retrieving a token.
	TokenURL string

	// AuthStyle represents how tokens are represented in requests.
	AuthStyle AuthStyle

	// RedirectURL is the URL to redirect users going through
	// the OAuth flow, after the resource owner's URLs.
	RedirectURL string

	// Scope specifies optional requested permissions.
	Scopes []string
}

// AuthStyle represents how requests for tokens are authenticated to the server.
type AuthStyle int

const (
	// AuthStyleAutoDetect means to auto-detect which authentication style the provider wants
	// by trying both ways and caching the successful way for the future.
	AuthStyleAutoDetect AuthStyle = 0

	// AuthStyleInParams sends the "client_id" and "client_secret" in the POST body
	// as application/x-www-form-urlencoded parameters.
	AuthStyleInParams AuthStyle = 1

	// AuthStyleInHeader sends the client_id and client_password using HTTP Basic Authorization.
	// This is an optional style described in the OAuth2 RFC 6749 section 2.3.1.
	AuthStyleInHeader AuthStyle = 2
)
