package http

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/supanut9/auth-server/internal/application"
	"github.com/supanut9/auth-server/internal/application/flow"
	"github.com/supanut9/auth-server/internal/application/identity"
	"github.com/supanut9/auth-server/internal/config"
	"github.com/supanut9/auth-server/internal/domain"
	"github.com/supanut9/auth-server/internal/port"
)

type goldenClock struct{ now time.Time }

func (c goldenClock) Now() time.Time { return c.now }

type goldenOTPCode struct{ code string }

func (g goldenOTPCode) NewCode() (string, error) { return g.code, nil }

// goldenOTPRepo implements only Create; the other methods are unused by
// StartOTPChallengeStateless.
type goldenOTPRepo struct {
	port.OTPChallengeRepository
	id string
}

func (r goldenOTPRepo) Create(_ context.Context, c domain.OTPChallenge) (domain.OTPChallenge, error) {
	c.ID = r.id
	return c, nil
}

// TestGoldenOTPStartResponse drives the real POST /v1/auth/otp/start handler:
// masked email + auth-ui /otp redirect_to built from the JSON body.
func TestGoldenOTPStartResponse(t *testing.T) {
	now := time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)
	clients := goldenClientRepo{
		"trading-web": {ClientID: "trading-web", ClientType: domain.ClientTypePublic, Status: domain.ClientStatusActive,
			RedirectURIs: []string{"https://trading.example.com/callback"}, AllowedScopes: "openid email profile"},
	}
	const challengeID = "0195f0a2-0000-7000-8000-0000000000aa"
	idSvc := identity.NewService(identity.Config{OTPChallengeTTL: 10 * time.Minute}, goldenClock{now: now}, nil,
		goldenOTPCode{code: "AbCd-_12"}, nil, nil, goldenOTPRepo{id: challengeID}, nil, flow.Service{})
	h := Handler{
		cfg: config.Config{AuthUIBaseURL: "https://auth-ui.example.com/"},
		app: application.App{Clients: clients, Identity: idSvc},
	}

	type otpCase struct {
		Name     string         `json:"name"`
		Body     string         `json:"request_body"`
		Response goldenResponse `json:"response"`
	}
	var cases []otpCase
	for _, in := range []otpCase{
		{Name: "trimmed_email_and_canonical_params", Body: `{"client_id":"trading-web","redirect_uri":"https://trading.example.com/callback","scope":"profile openid","state":"a b&c","nonce":"n","code_challenge":"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM","code_challenge_method":"S256","email":"  Alice.Smith@Example.com "}`},
		{Name: "response_type_and_prompt_echoed", Body: `{"response_type":"code","client_id":"trading-web","redirect_uri":"https://trading.example.com/callback","scope":"openid","state":"s","nonce":"n","code_challenge":"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM","code_challenge_method":"S256","prompt":"login","email":"ab@example.com"}`},
		{Name: "non_ascii_local_part", Body: `{"client_id":"trading-web","redirect_uri":"https://trading.example.com/callback","scope":"openid","state":"s","nonce":"n","code_challenge":"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM","code_challenge_method":"S256","email":"éa@example.com"}`},
		{Name: "public_client_plain_pkce_rejected", Body: `{"client_id":"trading-web","redirect_uri":"https://trading.example.com/callback","scope":"openid","state":"s","nonce":"n","code_challenge":"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM","email":"a@example.com"}`},
	} {
		c, rec := goldenContext(http.MethodPost, "/v1/auth/otp/start")
		c.Request, _ = http.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/auth/otp/start", strings.NewReader(in.Body))
		c.Request.Header.Set("Content-Type", "application/json")
		h.startOTPStateless(c)
		in.Response = goldenCapture(c, rec)
		cases = append(cases, in)
	}
	goldenSection(t, "redirects", "otp_start_response", map[string]any{
		"description":      "POST /v1/auth/otp/start (handlers_otp_consent_stateless.go startOTPStateless) with a fixed clock (now_unix), OTP_CHALLENGE_TTL=10m and challenge id. redirect_to = auth-ui /otp + body params as sent (response_type is NOT defaulted in the query even though validation defaults it) + otp_challenge_id + email=TrimSpace(body.email), url.Values.Encode (sorted). email = maskEmail(TrimSpace(body.email)) (see masking.json). expires_at = RFC3339 UTC.",
		"now_unix":         now.Unix(),
		"otp_challenge_id": challengeID,
		"auth_ui_base_url": h.cfg.AuthUIBaseURL,
		"clients":          clients,
		"cases":            cases,
	})
}
