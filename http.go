package eduoauth

import (
	"net/http"
)

// RoundTrip is a custom roundtripper for HTTP
// Inspired by https://github.com/golang/oauth2/blob/master/transport.go
type RoundTrip struct {
	// Token is the token which also contains a mutex
	Token *tokenLock
}

// RoundTrip is the overriden HTTP roundtripper that adds the bearer token
func (r *RoundTrip) RoundTrip(req *http.Request) (*http.Response, error) {
	if r.Token == nil {
		if req.Body != nil {
			req.Body.Close()
		}
		return nil, &TokensInvalidError{Cause: "tokens are empty"}
	}
	access, err := r.Token.Access(req.Context())
	if err != nil {
		if req.Body != nil {
			req.Body.Close()
		}
		return nil, err
	}

	reqClone := req.Clone(req.Context())
	reqClone.Header.Set("Authorization", "Bearer "+access)
	return http.DefaultTransport.RoundTrip(reqClone)
}
