package oauth

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/supanut9/auth-server/internal/domain"
)

type stubClientRepo struct {
	clients map[string]domain.OAuthClient
}

func (s stubClientRepo) Create(_ context.Context, c domain.OAuthClient) (domain.OAuthClient, error) {
	return c, nil
}

func (s stubClientRepo) FindByClientID(_ context.Context, clientID string) (domain.OAuthClient, error) {
	c, ok := s.clients[clientID]
	if !ok {
		return domain.OAuthClient{}, errors.New("not found")
	}
	return c, nil
}

func validPublicClient() domain.OAuthClient {
	return domain.OAuthClient{
		ClientID:      "trading-web",
		ClientType:    domain.ClientTypePublic,
		Status:        domain.ClientStatusActive,
		RedirectURIs:  []string{"https://trading.example.com/cb"},
		AllowedScopes: "openid email profile",
	}
}

func validConfidentialClient() domain.OAuthClient {
	c := validPublicClient()
	c.ClientID = "service"
	c.ClientType = domain.ClientTypeConfidential
	return c
}

// 64-char base64url (S256 typical) — passes both length and base64url checks.
const validChallenge = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_AB"

func validRequest() Request {
	return Request{
		ResponseType:        "code",
		ClientID:            "trading-web",
		RedirectURI:         "https://trading.example.com/cb",
		Scope:               "openid email profile",
		State:               "xyz",
		Nonce:               "n123",
		CodeChallenge:       validChallenge,
		CodeChallengeMethod: "S256",
	}
}

func newRepo(clients ...domain.OAuthClient) stubClientRepo {
	m := make(map[string]domain.OAuthClient, len(clients))
	for _, c := range clients {
		m[c.ClientID] = c
	}
	return stubClientRepo{clients: m}
}

func TestValidate_HappyPath(t *testing.T) {
	v, err := Validate(context.Background(), newRepo(validPublicClient()), validRequest())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got, want := v.Client.ClientID, "trading-web"; got != want {
		t.Fatalf("client: got %q want %q", got, want)
	}
	if got, want := strings.Join(v.Scopes, " "), "email openid profile"; got != want {
		t.Fatalf("scopes: got %q want %q", got, want)
	}
	if v.Request.Scope != "email openid profile" {
		t.Fatalf("canonical scope: got %q want %q", v.Request.Scope, "email openid profile")
	}
}

func TestValidate_FatalErrors(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*Request)
		code string
	}{
		{"missing client_id", func(r *Request) { r.ClientID = "" }, "invalid_request"},
		{"unknown client_id", func(r *Request) { r.ClientID = "nope" }, "invalid_client"},
		{"missing redirect_uri", func(r *Request) { r.RedirectURI = "" }, "invalid_request"},
		{"mismatched redirect_uri", func(r *Request) { r.RedirectURI = "https://evil.example.com/cb" }, "invalid_request"},
	}
	repo := newRepo(validPublicClient())
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := validRequest()
			tc.mut(&req)
			_, err := Validate(context.Background(), repo, req)
			if err == nil {
				t.Fatalf("expected error")
			}
			if err.Code != tc.code {
				t.Fatalf("error code: got %q want %q (%s)", err.Code, tc.code, err.Description)
			}
			if err.Recoverable {
				t.Fatalf("expected fatal (non-recoverable) error for %s", tc.name)
			}
		})
	}
}

func TestValidate_RecoverableErrors(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*Request)
		code string
	}{
		{"missing response_type", func(r *Request) { r.ResponseType = "" }, "invalid_request"},
		{"unsupported response_type", func(r *Request) { r.ResponseType = "token" }, "unsupported_response_type"},
		{"missing state", func(r *Request) { r.State = "" }, "invalid_request"},
		{"missing scope", func(r *Request) { r.Scope = "" }, "invalid_scope"},
		{"unauthorized scope", func(r *Request) { r.Scope = "openid admin" }, "invalid_scope"},
		{"openid missing nonce", func(r *Request) { r.Nonce = "" }, "invalid_request"},
		{"public client missing pkce", func(r *Request) { r.CodeChallenge = ""; r.CodeChallengeMethod = "" }, "invalid_request"},
		{"public client with plain pkce", func(r *Request) { r.CodeChallengeMethod = "plain" }, "invalid_request"},
		{"unsupported pkce method", func(r *Request) { r.CodeChallengeMethod = "S128" }, "invalid_request"},
		{"pkce challenge too short", func(r *Request) { r.CodeChallenge = "abc" }, "invalid_request"},
	}
	repo := newRepo(validPublicClient())
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := validRequest()
			tc.mut(&req)
			_, err := Validate(context.Background(), repo, req)
			if err == nil {
				t.Fatalf("expected error")
			}
			if err.Code != tc.code {
				t.Fatalf("error code: got %q want %q (%s)", err.Code, tc.code, err.Description)
			}
			if !err.Recoverable {
				t.Fatalf("expected recoverable error for %s", tc.name)
			}
		})
	}
}

func TestValidate_ConfidentialClientAllowsPlainPKCE(t *testing.T) {
	req := validRequest()
	req.ClientID = "service"
	req.CodeChallengeMethod = "plain"
	_, err := Validate(context.Background(), newRepo(validConfidentialClient()), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidate_ConfidentialClientAllowsMissingPKCE(t *testing.T) {
	req := validRequest()
	req.ClientID = "service"
	req.CodeChallenge = ""
	req.CodeChallengeMethod = ""
	_, err := Validate(context.Background(), newRepo(validConfidentialClient()), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidate_CanonicalizesScopeAndMethod(t *testing.T) {
	req := validRequest()
	req.Scope = "profile  email   openid email"
	req.CodeChallengeMethod = ""
	req.CodeChallenge = ""
	req.ClientID = "service"
	v, err := Validate(context.Background(), newRepo(validConfidentialClient()), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.Request.Scope != "email openid profile" {
		t.Fatalf("canonical scope: got %q", v.Request.Scope)
	}
}

func TestValidate_InactiveClientRejected(t *testing.T) {
	c := validPublicClient()
	c.Status = "disabled"
	_, err := Validate(context.Background(), newRepo(c), validRequest())
	if err == nil {
		t.Fatalf("expected error for inactive client")
	}
	if err.Code != "invalid_client" {
		t.Fatalf("error code: got %q want invalid_client", err.Code)
	}
	if err.Recoverable {
		t.Fatalf("inactive-client error should be fatal")
	}
}
