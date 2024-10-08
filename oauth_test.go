package eduoauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"
)

type refreshHandler struct {
	data []byte
	rc   int
}

func (h refreshHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.WriteHeader(h.rc)
	_, err := w.Write(h.data)
	if err != nil {
		panic(err)
	}
}

func assertError(t *testing.T, err error, wantErr string) {
	gv := ""
	if err != nil {
		gv = err.Error()
	}
	if wantErr != gv {
		if wantErr == "" {
			wantErr = "empty string"
		}
		t.Fatalf("Errors not equal, got: %v, want: %v", gv, wantErr)
	}
}

func TestRedirectURI(t *testing.T) {
	port := 0
	cases := []struct {
		redirect string
		want     string
	}{
		{
			redirect: "",
			want:     "http://127.0.0.1:1",
		},
		{
			redirect: "/",
			want:     "http://127.0.0.1:2/",
		},
		{
			redirect: "/callback",
			want:     "http://127.0.0.1:3/callback",
		},
	}
	for _, c := range cases {
		port++
		o := OAuth{RedirectPath: c.redirect}
		got := o.redirectURI(port)
		if got != c.want {
			t.Fatalf("redirect path not equal, got: %v, want: %v", got, c.want)
		}
	}
}

func TestAccessToken(t *testing.T) {
	o := OAuth{}
	ctx := context.Background()
	_, err := o.AccessToken(ctx)
	if err == nil {
		t.Fatalf("No error when getting access token on empty structure")
	}

	// Here we should get no error because the access token is set and is not expired
	want := "test"
	expired := time.Now().Add(1 * time.Hour)
	o = OAuth{token: &tokenLock{t: &tokenRefresher{Token: Token{Access: want, ExpiredTimestamp: expired}}}}
	got, err := o.AccessToken(ctx)
	if err != nil {
		t.Fatalf("Got error when getting access token on non-empty structure: %v", err)
	}
	if got != want {
		t.Fatalf("Access token not equal, Got: %v, Want: %v", got, want)
	}

	// Set the tokens as expired
	o.SetTokenExpired()

	// We should get an error because expired and no refresh token
	_, err = o.AccessToken(ctx)
	if err == nil {
		t.Fatal("Got no error when getting access token on non-empty structure and expired")
	}

	want = "test2"
	// Now we internally update the refresh function and refresh token, we should get new tokens
	refresh := "refresh"
	o.token.t.Refresh = refresh
	o.token.t.Refresher = func(_ context.Context, refreshToken string) (*TokenResponse, time.Time, error) {
		if refreshToken != refresh {
			t.Fatalf("Passed refresh token to refresher not equal to updated refresh token, got: %v, want: %v", refreshToken, refresh)
		}
		// Only the access and refresh fields are really important
		r := &TokenResponse{Access: want, Refresh: "test2"}
		return r, expired, nil
	}

	got, err = o.AccessToken(ctx)
	if err != nil {
		t.Fatalf("Got error when getting access token on non-empty expired structure and with a 'valid' refresh token: %v", err)
	}
	if got != want {
		t.Fatalf("Access token not equal, Got: %v, Want: %v", got, want)
	}

	// Set the tokens as expired
	o.SetTokenExpired()
	want = "test3"

	// Now let's act like a eduVPN 2.x server, we give no refresh token back. When we refresh the previous refresh token should be gotten
	o.token.t.Refresh = refresh
	prevRefresh := refresh
	o.token.t.Refresher = func(_ context.Context, refreshToken string) (*TokenResponse, time.Time, error) {
		if refreshToken != refresh {
			t.Fatalf("Passed refresh token to refresher not equal to updated refresh token, got: %v, want: %v", refreshToken, refresh)
		}
		// Only the access token is returned now
		r := &TokenResponse{Access: want}
		return r, expired, nil
	}

	got, err = o.AccessToken(ctx)
	if err != nil {
		t.Fatalf("Got error when getting access token on non-empty expired structure and with an empty refresh response: %v", err)
	}
	if got != want {
		t.Fatalf("Access token not equal, Got: %v, Want: %v", got, want)
	}
	if o.token.t.Refresh == "" {
		t.Fatalf("Refresh token is empty after refreshing and getting back an empty refresh")
	}
	if o.token.t.Refresh != prevRefresh {
		t.Fatalf("Refresh token is not equal to previous refresh token after refreshing and getting back an empty refresh token, got: %v, want: %v", o.token.t.Refresh, prevRefresh)
	}
}

func TestRefreshResponse(t *testing.T) {
	cases := []struct {
		rh      refreshHandler
		tr      *TokenResponse
		wantErr string
	}{
		{
			rh: refreshHandler{
				data: []byte(`
{
    "error": "invalid_grant",
    "error_description": "test"
}
				`),
				rc: 403,
			},
			wantErr: "tokens are invalid due to: got invalid_grant when refreshing the tokens with description: test",
		},
		{
			rh: refreshHandler{
				data: []byte(`
{
    "error": "invalid_grant"
}
				`),
				rc: 403,
			},
			wantErr: "tokens are invalid due to: got invalid_grant when refreshing the tokens with description: ",
		},
		{
			rh: refreshHandler{
				data: []byte(`
{
    "access_token": "newaccess",
    "refresh_token": "newrefresh",
    "token_type": "bearer",
    "expires_in": 3600
}
				`),
				rc: 200,
			},
			tr: &TokenResponse{
				Access:  "newaccess",
				Refresh: "newrefresh",
				Type:    "bearer",
				Expires: 3600,
			},
		},
	}

	for _, c := range cases {
		serv := httptest.NewServer(c.rh)
		defer serv.Close()
		o := OAuth{
			ClientID:  "test",
			UserAgent: "test",
			EndpointFunc: func(context.Context) (*EndpointResponse, error) {
				return &EndpointResponse{
					TokenURL: fmt.Sprintf("http://%s", serv.Listener.Addr().String()),
				}, nil
			},
		}

		o.UpdateTokens(Token{
			Access:           "accesstest",
			Refresh:          "refreshtest",
			ExpiredTimestamp: time.Now(),
		})

		tr, _, err := o.refreshResponse(context.Background(), "testrefreshtoken")
		if !reflect.DeepEqual(tr, c.tr) {
			t.Fatal("token responses are not equal")
		}
		assertError(t, err, c.wantErr)
	}
}

func TestSecretJSON(t *testing.T) {
	// Access and refresh tokens should not be present in marshalled JSON
	a := "ineedtobesecret_access"
	r := "ineedtobesecret_refresh"
	o := OAuth{token: &tokenLock{t: &tokenRefresher{Token: Token{Access: a, Refresh: r}}}}
	b, err := json.Marshal(o)
	if err != nil {
		t.Fatalf("Error when marshalling OAuth JSON: %v", err)
	}
	s := string(b)
	// Of course this is a very dumb check, it could be that we are writing in some other serialized format. However, we simply marshal the structure directly. Go just serializes this as a simple string
	if strings.Contains(s, a) {
		t.Fatalf("Serialized OAuth contains Access Token! Serialized: %v, Access Token: %v", s, a)
	}

	if strings.Contains(s, r) {
		t.Fatalf("Serialized OAuth contains Refresh Token! Serialized: %v, Refresh Token: %v", s, a)
	}
}

func TestAuthURL(t *testing.T) {
	id := "client_id"
	o := OAuth{ClientID: id, EndpointFunc: func(context.Context) (*EndpointResponse, error) {
		return &EndpointResponse{
			AuthorizationURL: "https://127.0.0.1/auth",
			TokenURL:         "https://127.0.0.1/token",
		}, nil
	}}
	scope := "test"
	s, err := o.AuthURL(context.Background(), "test")
	if err != nil {
		t.Fatalf("Error in getting OAuth URL: %v", err)
	}

	// Check if the OAuth session has valid values
	if o.session.State == "" {
		t.Fatal("No OAuth session state paremeter found")
	}
	if o.session.Verifier == "" {
		t.Fatal("No OAuth session state paremeter found")
	}
	if o.session.ErrChan == nil {
		t.Fatal("No OAuth session error channel found")
	}
	if o.session.Listener == nil {
		t.Fatal("No OAuth session listener found")
	}

	u, err := url.Parse(s)
	if err != nil {
		t.Fatalf("Returned Auth URL cannot be parsed with error: %v", err)
	}

	c := []struct {
		query string
		want  string
	}{
		{query: "client_id", want: id},
		{query: "code_challenge_method", want: "S256"},
		{query: "response_type", want: "code"},
		{query: "scope", want: scope},
		{query: "redirect_uri", want: o.session.RedirectURI},
	}

	q := u.Query()

	// We should have 7 parameters: client_id, challenge method, challenge, response type, scope, state and redirect uri
	if len(q) != 7 {
		t.Fatalf("Total query parameters is not 7, url: %v, total params: %v", u, len(q))
	}

	for _, v := range c {
		p := q.Get(v.query)
		if p != v.want {
			t.Fatalf("Parameter: %v, not equal, want: %v, got: %v", v.query, v.want, p)
		}
	}
}
