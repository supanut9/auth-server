// Package oauth contains the reusable OAuth/OIDC authorization-request validation
// and primitives shared by every action endpoint in the auth-server.
//
// The same Validate function is called by /v1/oauth2/authorize (UX gate — fail
// fast on broken client configs) and by every action endpoint (/login/google,
// /otp/start, /consent/accept, …) where it serves as the security gate. URL
// params are user-controllable, so each action must independently re-verify.
package oauth

import (
	"context"
	"encoding/base64"
	"errors"
	"net/url"
	"sort"
	"strings"

	"github.com/supanut9/auth-server/internal/domain"
	"github.com/supanut9/auth-server/internal/port"
)

// Request is the canonical OAuth 2.0 / OIDC authorization-request shape. It is
// the union of fields that any caller (the authorize redirect, an action POST,
// a provider callback) may need to act on.
type Request struct {
	ResponseType        string
	ClientID            string
	RedirectURI         string
	Scope               string // raw scope string as received
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	Prompt              string
}

// Validated wraps a request that has been verified against the client registry.
// Scopes are split + deduped; Request is canonicalised (whitespace trimmed,
// CodeChallengeMethod normalised to its OAuth value).
type Validated struct {
	Client  domain.OAuthClient
	Scopes  []string
	Request Request
}

// Error is the structured failure returned from Validate. Code matches the OAuth
// 2.0 error registry (RFC 6749 §4.1.2.1, §5.2). Description is a human-readable
// hint suitable for the UI; never include secrets.
//
// Recoverable distinguishes errors where the OAuth spec requires us to redirect
// back to the client's redirect_uri with ?error=... (the request was structurally
// valid enough to do so) from "fatal" errors (invalid client / invalid
// redirect_uri) where we must NOT redirect and should render a server-side error.
type Error struct {
	Code        string
	Description string
	Recoverable bool
}

func (e *Error) Error() string {
	return e.Code + ": " + e.Description
}

// supportedResponseTypes — only "code" today. Implicit and hybrid flows are
// intentionally not supported (best practice as of OAuth 2.1).
var supportedResponseTypes = map[string]struct{}{
	"code": {},
}

// supportedPKCEMethods — "S256" everywhere; "plain" only for confidential
// clients per the spec compliance audit (A3). Public clients MUST use S256.
var supportedPKCEMethods = map[string]struct{}{
	"S256":  {},
	"plain": {},
}

// Validate checks an OAuth authorization request against the registered client.
// The clients repo is the only side-effect; everything else is pure.
//
// Order matters: we resolve the client first because the rest of the errors
// determine whether we can safely redirect to its redirect_uri. Errors before
// the client is resolved are non-recoverable (we don't trust the redirect_uri
// yet). Errors after the redirect_uri is validated against the client are
// recoverable per RFC 6749.
func Validate(ctx context.Context, clients port.OAuthClientRepository, req Request) (Validated, *Error) {
	if req.ClientID == "" {
		return Validated{}, &Error{Code: "invalid_request", Description: "client_id is required"}
	}

	client, err := clients.FindByClientID(ctx, req.ClientID)
	if err != nil {
		return Validated{}, &Error{Code: "invalid_client", Description: "client_id is unknown"}
	}

	if client.Status != "" && client.Status != domain.ClientStatusActive {
		return Validated{}, &Error{Code: "invalid_client", Description: "client is not active"}
	}

	if req.RedirectURI == "" {
		return Validated{}, &Error{Code: "invalid_request", Description: "redirect_uri is required"}
	}
	if !containsExact(client.RedirectURIs, req.RedirectURI) {
		return Validated{}, &Error{Code: "invalid_request", Description: "redirect_uri does not match a registered URI"}
	}
	if parsed, perr := url.Parse(req.RedirectURI); perr != nil || parsed.Scheme == "" || parsed.Host == "" {
		return Validated{}, &Error{Code: "invalid_request", Description: "redirect_uri must be an absolute URL"}
	}

	// From here on the redirect_uri is trusted enough to bounce errors back to
	// the client per OAuth spec — flip Recoverable on subsequent failures.
	recoverable := func(code, description string) *Error {
		return &Error{Code: code, Description: description, Recoverable: true}
	}

	if req.ResponseType == "" {
		return Validated{}, recoverable("invalid_request", "response_type is required")
	}
	if _, ok := supportedResponseTypes[req.ResponseType]; !ok {
		return Validated{}, recoverable("unsupported_response_type", "response_type must be code")
	}

	if req.State == "" {
		return Validated{}, recoverable("invalid_request", "state is required")
	}

	scopes := splitScopes(req.Scope)
	if len(scopes) == 0 {
		return Validated{}, recoverable("invalid_scope", "scope is required")
	}
	allowed := splitScopes(client.AllowedScopes)
	if !subset(scopes, allowed) {
		return Validated{}, recoverable("invalid_scope", "requested scopes are not allowed for this client")
	}

	if containsExact(scopes, "openid") && req.Nonce == "" {
		return Validated{}, recoverable("invalid_request", "nonce is required for openid")
	}

	method := req.CodeChallengeMethod
	if method == "" && req.CodeChallenge != "" {
		method = "plain"
	}
	if client.ClientType == domain.ClientTypePublic && req.CodeChallenge == "" {
		return Validated{}, recoverable("invalid_request", "code_challenge is required for public clients")
	}
	if req.CodeChallenge != "" {
		if _, ok := supportedPKCEMethods[method]; !ok {
			return Validated{}, recoverable("invalid_request", "unsupported code_challenge_method")
		}
		if client.ClientType == domain.ClientTypePublic && method == "plain" {
			return Validated{}, recoverable("invalid_request", "public clients must use S256 for code_challenge_method")
		}
		// base64url with no padding, 43–128 chars per RFC 7636 §4.2
		if l := len(req.CodeChallenge); l < 43 || l > 128 {
			return Validated{}, recoverable("invalid_request", "code_challenge length must be 43–128 characters")
		}
		if _, err := base64.RawURLEncoding.DecodeString(req.CodeChallenge); err != nil {
			return Validated{}, recoverable("invalid_request", "code_challenge must be base64url-encoded without padding")
		}
	}

	canonical := req
	canonical.CodeChallengeMethod = method
	canonical.Scope = strings.Join(scopes, " ")

	return Validated{
		Client:  client,
		Scopes:  scopes,
		Request: canonical,
	}, nil
}

// IsFatal reports whether the error must be rendered server-side (no redirect).
// Helper for handlers to keep their error branching tight.
func IsFatal(err *Error) bool {
	if err == nil {
		return false
	}
	return !err.Recoverable
}

// ErrNotFound is returned by adapters that wrap repository misses, so handlers
// can distinguish "client doesn't exist" from transport errors.
var ErrNotFound = errors.New("oauth: not found")

// ---------- helpers (small enough to keep in this file) ----------

func splitScopes(raw string) []string {
	if raw == "" {
		return nil
	}
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ' ' || r == ',' || r == '\n' || r == '\t'
	})
	seen := make(map[string]struct{}, len(fields))
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if _, ok := seen[f]; ok {
			continue
		}
		seen[f] = struct{}{}
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}

func containsExact(items []string, needle string) bool {
	for _, item := range items {
		if item == needle {
			return true
		}
	}
	return false
}

func subset(requested []string, allowed []string) bool {
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, item := range allowed {
		allowedSet[item] = struct{}{}
	}
	for _, item := range requested {
		if _, ok := allowedSet[item]; !ok {
			return false
		}
	}
	return true
}
