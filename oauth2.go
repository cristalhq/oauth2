package oauth2

// Config describes a 3-legged OAuth2 flow.
type Config struct {
	ClientID     string   // ClientID is the application's ID.
	ClientSecret string   // ClientSecret is the application's secret.
	AuthURL      string   // AuthURL is a URL for authentication.
	TokenURL     string   // TokenURL is a URL for retrieving a token.
	Mode         Mode     // Mode represents how tokens are represented in requests.
	RedirectURL  string   // RedirectURL is the URL to redirect users going through the OAuth flow.
	Scopes       []string // Scope specifies optional requested permissions.
}

// Mode represents how requests for tokens are authenticated to the server.
type Mode int

const (
	// AutoDetectMode means to auto-detect which authentication style the provider wants.
	AutoDetectMode Mode = 0

	// InParamsMode sends the `client_id` and `client_secret` in the POST body
	// as application/x-www-form-urlencoded parameters.
	InParamsMode Mode = 1

	// InHeaderMode sends the `client_id` and `client_secret` using HTTP Basic Authorization.
	// This is an optional style described in the OAuth2 RFC 6749 section 2.3.1.
	InHeaderMode Mode = 2
)
