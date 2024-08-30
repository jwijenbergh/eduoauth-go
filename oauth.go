// Package eduoauth implement an oauth client defined in e.g. rfc 6749
// However, we try to follow some recommendations from the v2.1 oauth draft RFC
// Some specific things we implement here:
// - PKCE (RFC 7636)
// - We only support bearer tokens
package eduoauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// EndpointResponse is the response for getting the authorization and token URL
type EndpointResponse struct {
	// AuthorizationURL is the OAuth url for authorization
	AuthorizationURL string
	// TokenURL is the OAuth url for getting (new) tokens
	TokenURL string
}

// OAuth defines the main structure for this package.
type OAuth struct {
	// The cached client id so we don't have to pass it around
	ClientID string

	// The HTTP client that is used
	httpClient *http.Client

	// EndpointFunc is the function to get the token and authorization URLs
	EndpointFunc func(context.Context) (*EndpointResponse, error) `json:"-"`

	// CustomRedirect is a redirect URI. it specifies whether or not a custom redirect URI should be used
	CustomRedirect string

	// RedirectPath is the path of the redirect, this is only used if a custom redirect is not given
	RedirectPath string

	// TokensUpdated is the function that is called when tokens are updated
	TokensUpdated func(tok Token) `json:"-"`

	// Transport is the inner HTTP roundtripper to use
	Transport http.RoundTripper

	// UserAgent is the HTTP user agent to use for requests made by this library
	// Empty string means it will not be set and it will be the default Go user agent
	UserAgent string

	// session is the internal in progress OAuth session
	session exchangeSession

	// cachedEndpoints are the cached token endpoints
	cachedEndpoints *EndpointResponse

	// Token is where the access and refresh tokens are stored along with the timestamps
	// It is protected by a lock
	token *tokenLock
}

func (oauth *OAuth) tokenEndpoints(ctx context.Context) (*EndpointResponse, error) {
	if oauth.EndpointFunc == nil {
		return nil, errors.New("no token endpoint updater function available")
	}
	ep, err := oauth.EndpointFunc(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get OAuth endpoints: %w", err)
	}
	oauth.cachedEndpoints = ep
	return ep, nil
}

// AccessToken gets the OAuth access token used for contacting the server API
// It returns the access token as a string, possibly obtained fresh using the Refresh Token
// If the token cannot be obtained, an error is returned and the token is an empty string.
func (oauth *OAuth) AccessToken(ctx context.Context) (string, error) {
	tl := oauth.token
	if tl == nil {
		return "", &TokensInvalidError{Cause: "no token structure available"}
	}
	return tl.Access(ctx)
}

// NewHTTPClient returns a new HTTP client
// Note: This does not have the UserAgent automatically added to each request
// You can set it yourself on the requests you do with the client
func (oauth *OAuth) NewHTTPClient() *http.Client {
	return &http.Client{
		Transport: &RoundTrip{
			Token:     oauth.token,
			Transport: oauth.transport(),
		},
	}
}

// setupListener sets up an OAuth listener
// If it was unsuccessful it returns an error.
// @see https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-07.html#section-8.4.2
// "Loopback Interface Redirection".
func (oauth *OAuth) setupListener() (net.Listener, error) {
	// create a listener
	lst, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("net.Listen failed with error: %w", err)
	}
	return lst, nil
}

// tokensWithCallback gets the OAuth tokens using a local web server
// If it was unsuccessful it returns an error.
func (oauth *OAuth) tokensWithCallback(ctx context.Context) error {
	if oauth.session.Listener == nil {
		return errors.New("failed getting tokens with callback: no listener")
	}
	mux := http.NewServeMux()
	// server /callback over the listener address
	s := &http.Server{
		Handler: mux,
		// Define a default 60 second header read timeout to protect against a Slowloris Attack
		// A bit overkill maybe for a local server but good to define anyways
		ReadHeaderTimeout: 60 * time.Second,
	}
	defer s.Shutdown(ctx) //nolint:errcheck

	// Use a sync.Once to only handle one request up until we shutdown the server
	var once sync.Once
	mux.HandleFunc(oauth.RedirectPath, func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() {
			oauth.Handler(w, r)
		})
	})

	go func() {
		if err := s.Serve(oauth.session.Listener); err != http.ErrServerClosed {
			oauth.session.ErrChan <- fmt.Errorf("failed getting tokens with callback and error: %w", err)
		}
	}()
	select {
	case err := <-oauth.session.ErrChan:
		return err
	case <-ctx.Done():
		return fmt.Errorf("stopped oauth server: %w", context.Canceled)
	}
}

// tokenResponse fills the OAuth token response structure by the response
// The URL that is input here is used for additional context
// It returns this structure and an error if there is one
func (oauth *OAuth) tokenResponse(reader io.Reader) (*TokenResponse, error) {
	if oauth.token == nil {
		return nil, errors.New("no oauth structure when filling token")
	}
	res := TokenResponse{}

	decoder := json.NewDecoder(reader)
	err := decoder.Decode(&res)
	if err != nil {
		return nil, fmt.Errorf("failed to decode JSON: %w", err)
	}

	return &res, nil
}

// SetTokenExpired marks the tokens as expired by setting the expired timestamp to the current time.
func (oauth *OAuth) SetTokenExpired() {
	if oauth.token != nil {
		oauth.token.SetExpired()
	}
}

// SetTokenRenew sets the tokens for renewal by completely clearing the structure.
func (oauth *OAuth) SetTokenRenew() {
	if oauth.token != nil {
		oauth.token.Update(Token{})
	}
}

// Token returns the token structure
func (oauth *OAuth) Token() Token {
	t := Token{}
	if oauth.token != nil {
		t = oauth.token.Get()
	}

	return t
}

func checkResponse(res http.Response) (io.Reader, error) {
	read := http.MaxBytesReader(nil, res.Body, 10<<20)
	ok := res.StatusCode >= 200 && res.StatusCode < 300
	// status code is ok just return so we can use the reader later
	if ok {
		return read, nil
	}
	return read, fmt.Errorf("request was not successful, http code: '%v'", res.StatusCode)
}

// tokensWithAuthCode gets the access and refresh tokens using the authorization code
// Access tokens: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-04#section-1.4
// Refresh tokens: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-04#section-1.3.2
// If it was unsuccessful it returns an error.
func (oauth *OAuth) tokensWithAuthCode(ctx context.Context, authCode string) error {
	// Make sure the verifier is set as the parameter
	// so that the server can verify that we are the actual owner of the authorization code
	data := url.Values{
		"client_id":     {oauth.ClientID},
		"code":          {authCode},
		"code_verifier": {oauth.session.Verifier},
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {oauth.session.RedirectURI},
	}
	now := time.Now()

	if oauth.cachedEndpoints == nil {
		return errors.New("cannot get tokens with authorization code as no endpoints have been fetched before")
	}

	req, err := http.NewRequestWithContext(ctx, "POST", oauth.cachedEndpoints.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return err
	}
	req.Header.Add("content-type", "application/x-www-form-urlencoded")
	if oauth.UserAgent != "" {
		req.Header.Add("User-Agent", oauth.UserAgent)
	}

	res, err := oauth.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	// response is guaranteed to be non-nil here so we can dereference it
	read, err := checkResponse(*res)
	if err != nil {
		// else just read the whole body to get the error response and return
		b, rerr := io.ReadAll(read)
		if err != nil {
			// We do error: %v here and not %w is because we do not want to wrap the error
			// As it is not the actual cause of the error
			// It is just there for misc info
			return fmt.Errorf("request was not successful: %v, could not read body with error: %v", err, rerr)
		}
		return fmt.Errorf("request was not successful: %v, body: %v", err, b)
	}

	tr, err := oauth.tokenResponse(read)
	if err != nil {
		return err
	}
	if tr == nil {
		return errors.New("no token response after authorization code")
	}

	oauth.token.UpdateResponse(*tr, now)
	return nil
}

// UpdateTokens internally sets the tokens to `t`
func (oauth *OAuth) UpdateTokens(t Token) {
	if oauth.token == nil {
		oauth.token = &tokenLock{t: &tokenRefresher{Refresher: oauth.refreshResponse, Updated: oauth.TokensUpdated}}
	}
	oauth.token.Update(t)
}

type errorResponse struct {
	Error       string `json:"error"`
	Description string `json:"error_description"`
}

func (oauth *OAuth) transport() http.RoundTripper {
	if oauth.Transport == nil {
		return http.DefaultTransport
	}
	return oauth.Transport
}

// refreshResponse gets the refresh token response with a refresh token
// This response contains the access and refresh tokens, together with a timestamp
// Access tokens: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-04#section-1.4
// Refresh tokens: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-04#section-1.3.2
// If it was unsuccessful it returns an error.
func (oauth *OAuth) refreshResponse(ctx context.Context, r string) (*TokenResponse, time.Time, error) {
	ep, err := oauth.tokenEndpoints(ctx)
	if err != nil {
		return nil, time.Time{}, err
	}
	u := ep.TokenURL
	if oauth.token == nil {
		return nil, time.Time{}, errors.New("no oauth token structure in refresh")
	}
	if oauth.ClientID == "" {
		return nil, time.Time{}, errors.New("no client ID was cached for refresh")
	}
	// Test if we have a http client and if not recreate one
	if oauth.httpClient == nil {
		oauth.httpClient = &http.Client{Transport: oauth.transport()}
	}

	data := url.Values{
		"client_id":     {oauth.ClientID},
		"refresh_token": {r},
		"grant_type":    {"refresh_token"},
	}
	now := time.Now()

	req, err := http.NewRequestWithContext(ctx, "POST", u, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, time.Time{}, err
	}
	req.Header.Add("content-type", "application/x-www-form-urlencoded")
	if oauth.UserAgent != "" {
		req.Header.Add("User-Agent", oauth.UserAgent)
	}

	res, err := oauth.httpClient.Do(req)
	if err != nil {
		return nil, time.Time{}, err
	}
	defer res.Body.Close()
	read, err := checkResponse(*res)
	if err != nil {
		errRes := errorResponse{}
		decoder := json.NewDecoder(read)
		derr := decoder.Decode(&errRes)
		if derr != nil {
			return nil, time.Time{}, fmt.Errorf("failed to decode refresh token response: %w", derr)
		}
		if errRes.Error == "invalid_grant" {
			return nil, time.Time{}, &TokensInvalidError{Cause: fmt.Sprintf("got invalid_grant when refreshing the tokens with description: %v", errRes.Description)}
		}
		return nil, time.Time{}, fmt.Errorf("refresh token error is not invalid_grant: '%s'", errRes.Error)
	}

	tr, err := oauth.tokenResponse(read)
	return tr, now, err
}

// ResponseTemplate is the HTML template for the OAuth authorized response
// this template was dapted from: https://github.com/eduvpn/apple/blob/5b18f834be7aebfed00570ae0c2f7bcbaf1c69cc/EduVPN/Helpers/Mac/OAuthRedirectHTTPHandler.m#L25
const ResponseTemplate string = `
<!DOCTYPE html>
<html dir="ltr" xmlns="http://www.w3.org/1999/xhtml" lang="en"><head>
<meta http-equiv="content-type" content="text/html; charset=UTF-8">
<meta charset="utf-8">
<title>{{.Title}}</title>
<style>
body {
    font-family: arial;
    margin: 0;
    height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    background: #ccc;
    color: #252622;
}
main {
    padding: 1em 2em;
    text-align: center;
    border: 2pt solid #666;
    box-shadow: rgba(0, 0, 0, 0.6) 0px 1px 4px;
    border-color: #aaa;
    background: #ddd;
}
</style>
</head>
<body>
    <main>
        <h1>{{.Title}}</h1>
        <p>{{.Message}}</p>
    </main>
</body>
</html>
`

// oauthResponseHTML is a structure that is used to give back the OAuth response.
type oauthResponseHTML struct {
	Title   string
	Message string
}

// writeResponseHTML writes the OAuth response using a response writer and the title + message
// If it was unsuccessful it returns an error.
func writeResponseHTML(w http.ResponseWriter, title string, message string) error {
	t, err := template.New("oauth-response").Parse(ResponseTemplate)
	if err != nil {
		return fmt.Errorf("failed writing response HTML with error: %w", err)
	}

	return t.Execute(w, oauthResponseHTML{Title: title, Message: message})
}

// exchangeSession is a structure that gets passed to the callback for easy access to the current state.
type exchangeSession struct {
	// State is the expected URL state parameter
	State string

	// Verifier is the preimage of the challenge
	Verifier string

	// RedirectURI is the passed redirect URI
	RedirectURI string

	// Listener is the listener where the servers 'listens' on
	Listener net.Listener

	// ErrChan is used to send the error from the handler
	ErrChan chan error
}

func (oauth *OAuth) redirectURI(port int) string {
	// TODO: properly verify that the path contains no .. (or clean it)
	// And that it contains at least a / when nonempty
	// However this does not revolve around user input just yet
	return fmt.Sprintf("http://127.0.0.1:%d%s", port, oauth.RedirectPath)
}

// authcode gets the authorization code from the url
// It returns the code and an error if there is one
func (s *exchangeSession) Authcode(url *url.URL) (string, error) {
	q := url.Query()
	// Make sure the state is present and matches to protect against cross-site request forgeries
	// https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-04#section-7.15
	state := q.Get("state")
	if state == "" {
		return "", fmt.Errorf("failed retrieving parameter 'state' from '%s'", url)
	}
	// The state is the first entry
	if state != s.State {
		return "", fmt.Errorf("failed matching state; expected '%s' got '%s'", s.State, state)
	}

	// check if an error is present
	// https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-09#name-authorization-response (error response)
	errc := q.Get("error")
	if errc != "" {
		// these are optional but let's include them
		errdesc := q.Get("error_description")
		erruri := q.Get("error_uri")
		return "", fmt.Errorf("failed obtaining oauthorization code, error code '%s', error description '%s', error uri '%s'", errc, errdesc, erruri)
	}

	// No authorization code
	code := q.Get("code")
	if code == "" {
		return "", fmt.Errorf("failed retrieving parameter 'code' from '%s'", url)
	}

	return code, nil
}

// tokenHandler gets the tokens using the authorization code that is obtained through the url
// This function is called by the http handler and returns an error if the tokens cannot be obtained
func (oauth *OAuth) tokenHandler(ctx context.Context, url *url.URL) error {
	// Get the authorization code
	c, err := oauth.session.Authcode(url)
	if err != nil {
		return err
	}
	// Now that we have obtained the authorization code, we can move to the next step:
	// Obtaining the access and refresh tokens
	return oauth.tokensWithAuthCode(ctx, c)
}

// Handler is the function used to get the OAuth tokens using an authorization code callback
// The callback to retrieve the authorization code: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-04#section-1.3.1
// It sends an error to the session channel (can be nil)
func (oauth *OAuth) Handler(w http.ResponseWriter, req *http.Request) {
	err := oauth.tokenHandler(req.Context(), req.URL)
	if err != nil {
		_ = writeResponseHTML(
			w,
			"Authorization Failed",
			"The authorization has failed. See the log file for more information.",
		)
	} else {
		_ = writeResponseHTML(w, "Authorized", "The client has been successfully authorized. You can close this browser window.")
	}
	oauth.session.ErrChan <- err
}

// AuthURL gets the authorization url to start the OAuth procedure.
func (oauth *OAuth) AuthURL(ctx context.Context, scope string) (string, error) {
	// TODO: Enforce redirect path here for eduvpn-common?
	// Generate the verifier and challenge
	v, err := genVerifier()
	if err != nil {
		return "", fmt.Errorf("genVerifier error: %w", err)
	}

	// Generate the state
	state, err := genState()
	if err != nil {
		return "", fmt.Errorf("genState error: %w", err)
	}

	// Re-initialize the token structure
	oauth.UpdateTokens(Token{})

	// Fill the struct with the necessary fields filled for the next call to getting the HTTP client
	red := oauth.CustomRedirect

	var l net.Listener
	if red == "" {
		var lerr error
		// set up the listener to get the redirect URI
		l, lerr = oauth.setupListener()
		if lerr != nil {
			return "", fmt.Errorf("oauth.setupListener error: %w", err)
		}
		port := l.Addr().(*net.TCPAddr).Port
		red = fmt.Sprintf("http://127.0.0.1:%d%s", port, oauth.RedirectPath)
	}
	oauth.session = exchangeSession{
		State:       state,
		Verifier:    v,
		ErrChan:     make(chan error),
		RedirectURI: red,
		Listener:    l,
	}

	params := map[string]string{
		"client_id":             oauth.ClientID,
		"code_challenge_method": "S256",
		"code_challenge":        genChallengeS256(v),
		"response_type":         "code",
		"scope":                 scope,
		"state":                 state,
		"redirect_uri":          red,
	}

	ep, err := oauth.tokenEndpoints(ctx)
	if err != nil {
		return "", err
	}

	// construct the URL with the parameters
	u, err := url.Parse(ep.AuthorizationURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse OAuth base URL '%s', with error: %w", ep.AuthorizationURL, err)
	}

	q := u.Query()
	for p, value := range params {
		q.Set(p, value)
	}
	u.RawQuery = q.Encode()

	// Return the url processed
	return u.String(), nil
}

func (oauth *OAuth) tokensWithURI(ctx context.Context, uri string) error {
	// parse URI
	p, err := url.Parse(uri)
	if err != nil {
		return err
	}
	return oauth.tokenHandler(ctx, p)
}

// Exchange starts the OAuth exchange by getting the tokens with the redirect callback
// If it was unsuccessful it returns an error.
func (oauth *OAuth) Exchange(ctx context.Context, uri string) error {
	// If there is no HTTP client defined, create a new one
	if oauth.httpClient == nil {
		oauth.httpClient = &http.Client{Transport: oauth.transport()}
	}
	if uri != "" {
		return oauth.tokensWithURI(ctx, uri)
	}
	if oauth.CustomRedirect != "" {
		return errors.New("a custom redirect is initialized but no authorization uri response is given by the client")
	}
	return oauth.tokensWithCallback(ctx)
}

// TokensInvalidError is the error that is returned when the tokens are deemed to be invalid
// E.g. due to getting invalid grant when refreshing tokens or when no token is returned
type TokensInvalidError struct {
	Cause string
}

func (e *TokensInvalidError) Error() string {
	return fmt.Sprintf("tokens are invalid due to: %s", e.Cause)
}
