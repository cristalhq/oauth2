# oauth2

[![Build Status][build-img]][build-url]
[![GoDoc][doc-img]][doc-url]
[![Go Report Card][reportcard-img]][reportcard-url]
[![Coverage][coverage-img]][coverage-url]

OAuth2 client in Go.

## Features

* Simple API.
* Tiny codebase.
* Dependency-free.

## Install

Go version 1.13

```
go get github.com/cristalhq/oauth2
```

## Example

```go
config := oauth2.Config{
    ClientID:     "YOUR_CLIENT_ID",
    ClientSecret: "YOUR_CLIENT_SECRET",
    AuthURL:      "https://provider.com/o/oauth2/auth",
    TokenURL:     "https://provider.com/o/oauth2/token",
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
```

## Documentation

See [these docs](https://godoc.org/github.com/cristalhq/oauth2).

## License

[MIT License](LICENSE).

[build-img]: https://github.com/cristalhq/oauth2/workflows/build/badge.svg
[build-url]: https://github.com/cristalhq/oauth2/actions
[doc-img]: https://godoc.org/github.com/cristalhq/oauth2?status.svg
[doc-url]: https://godoc.org/github.com/cristalhq/oauth2
[reportcard-img]: https://goreportcard.com/badge/cristalhq/oauth2
[reportcard-url]: https://goreportcard.com/report/cristalhq/oauth2
[coverage-img]: https://codecov.io/gh/cristalhq/oauth2/branch/master/graph/badge.svg
[coverage-url]: https://codecov.io/gh/cristalhq/oauth2
