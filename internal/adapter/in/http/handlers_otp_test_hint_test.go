package http

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/supanut9/auth-server/internal/application"
	"github.com/supanut9/auth-server/internal/config"
	"github.com/supanut9/auth-server/internal/domain"
	"github.com/supanut9/auth-server/internal/port"
)

// stubOTPChallengeRepository is a minimal in-memory stub that satisfies
// port.OTPChallengeRepository for test-hint handler tests.
type stubOTPChallengeRepository struct {
	challenges []domain.OTPChallenge
}

func (s *stubOTPChallengeRepository) Create(_ context.Context, c domain.OTPChallenge) (domain.OTPChallenge, error) {
	s.challenges = append(s.challenges, c)
	return c, nil
}

func (s *stubOTPChallengeRepository) FindActiveByRequestAndEmail(_ context.Context, _ string, _ string) (domain.OTPChallenge, error) {
	return domain.OTPChallenge{}, fmt.Errorf("not found")
}

func (s *stubOTPChallengeRepository) FindByID(_ context.Context, id string) (domain.OTPChallenge, error) {
	for _, c := range s.challenges {
		if c.ID == id {
			return c, nil
		}
	}
	return domain.OTPChallenge{}, fmt.Errorf("not found")
}

func (s *stubOTPChallengeRepository) Update(_ context.Context, c domain.OTPChallenge) (domain.OTPChallenge, error) {
	for i, existing := range s.challenges {
		if existing.ID == c.ID {
			s.challenges[i] = c
			return c, nil
		}
	}
	return domain.OTPChallenge{}, fmt.Errorf("not found")
}

func (s *stubOTPChallengeRepository) FindLatestActiveByEmail(_ context.Context, email string) (domain.OTPChallenge, error) {
	now := time.Now().UTC()
	var best *domain.OTPChallenge
	for i := range s.challenges {
		c := &s.challenges[i]
		if c.Email != email {
			continue
		}
		if c.VerifiedAt != nil {
			continue
		}
		if now.After(c.ExpiresAt) {
			continue
		}
		if best == nil || c.CreatedAt.After(best.CreatedAt) {
			best = c
		}
	}
	if best == nil {
		return domain.OTPChallenge{}, fmt.Errorf("not found")
	}
	return *best, nil
}

// newTestHintRouter builds a gin router wired for test-hint endpoint testing.
func newTestHintRouter(t *testing.T, cfg config.Config, repo port.OTPChallengeRepository) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	app := application.App{OTPChallenges: repo}
	RegisterRoutes(router, cfg, nil, app)
	return router
}

func TestOTPTestHintRefusesInProduction(t *testing.T) {
	t.Parallel()

	repo := &stubOTPChallengeRepository{}
	cfg := config.Config{
		AppEnv:               "production",
		AuthUIBaseURL:        "https://auth.example.com",
		SupportAPIToken:      "tok",
		OTPTestHintAllowlist: []string{"ci@example.com"},
	}
	router := newTestHintRouter(t, cfg, repo)

	req := httptest.NewRequest(http.MethodGet, "/v1/auth/otp/test-hint?email=ci@example.com", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	// Route is not mounted in production — expect 404 from gin's default handler.
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 in production, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestOTPTestHintRefusesWhenAllowlistEmpty(t *testing.T) {
	t.Parallel()

	repo := &stubOTPChallengeRepository{}
	cfg := config.Config{
		AppEnv:               "development",
		AuthUIBaseURL:        "https://auth.example.com",
		SupportAPIToken:      "tok",
		OTPTestHintAllowlist: nil, // unset
	}
	router := newTestHintRouter(t, cfg, repo)

	req := httptest.NewRequest(http.MethodGet, "/v1/auth/otp/test-hint?email=ci@example.com", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when allowlist empty, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestOTPTestHintRefusesUnallowlistedEmail(t *testing.T) {
	t.Parallel()

	repo := &stubOTPChallengeRepository{}
	cfg := config.Config{
		AppEnv:               "staging",
		AuthUIBaseURL:        "https://auth.example.com",
		SupportAPIToken:      "tok",
		OTPTestHintAllowlist: []string{"allowed@example.com"},
	}
	router := newTestHintRouter(t, cfg, repo)

	req := httptest.NewRequest(http.MethodGet, "/v1/auth/otp/test-hint?email=notallowed@example.com", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for non-allowlisted email, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestOTPTestHintRefusesWhenNoChallengeExists(t *testing.T) {
	t.Parallel()

	repo := &stubOTPChallengeRepository{} // empty
	cfg := config.Config{
		AppEnv:               "development",
		AuthUIBaseURL:        "https://auth.example.com",
		SupportAPIToken:      "tok",
		OTPTestHintAllowlist: []string{"ci@example.com"},
	}
	router := newTestHintRouter(t, cfg, repo)

	req := httptest.NewRequest(http.MethodGet, "/v1/auth/otp/test-hint?email=ci@example.com", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when no active challenge, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestOTPTestHintReturnsActiveChallengeInDevelopment(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	repo := &stubOTPChallengeRepository{
		challenges: []domain.OTPChallenge{
			{
				ID:        "test-challenge-id",
				Email:     "ci@example.com",
				CodeHash:  "abcdefghijklmnop",
				ExpiresAt: now.Add(10 * time.Minute),
				CreatedAt: now,
			},
		},
	}
	cfg := config.Config{
		AppEnv:               "development",
		AuthUIBaseURL:        "https://auth.example.com",
		SupportAPIToken:      "tok",
		OTPTestHintAllowlist: []string{"ci@example.com"},
	}
	router := newTestHintRouter(t, cfg, repo)

	req := httptest.NewRequest(http.MethodGet, "/v1/auth/otp/test-hint?email=ci@example.com", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var payload struct {
		OTPChallengeID string `json:"otp_challenge_id"`
		Email          string `json:"email"`
		CodeHashPrefix string `json:"code_hash_prefix"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload.OTPChallengeID != "test-challenge-id" {
		t.Fatalf("unexpected challenge id: %q", payload.OTPChallengeID)
	}
	if payload.Email != "ci@example.com" {
		t.Fatalf("unexpected email: %q", payload.Email)
	}
	if payload.CodeHashPrefix != "abcdefgh" {
		// first 8 chars of the code hash
		t.Fatalf("unexpected code_hash_prefix: %q", payload.CodeHashPrefix)
	}
}

func TestOTPTestHintHandlerRefusesProductionDirectly(t *testing.T) {
	t.Parallel()

	// Even if someone bypasses the route-not-mounted check, the handler
	// itself must still refuse.
	gin.SetMode(gin.TestMode)
	cfg := config.Config{
		AppEnv:               "production",
		AuthUIBaseURL:        "https://auth.example.com",
		SupportAPIToken:      "tok",
		OTPTestHintAllowlist: []string{"ci@example.com"},
	}
	repo := &stubOTPChallengeRepository{
		challenges: []domain.OTPChallenge{
			{
				ID:        "ch-1",
				Email:     "ci@example.com",
				CodeHash:  "abcdefghijklmnop",
				ExpiresAt: time.Now().UTC().Add(10 * time.Minute),
				CreatedAt: time.Now().UTC(),
			},
		},
	}
	handler := Handler{cfg: cfg, app: application.App{OTPChallenges: repo}}

	router := gin.New()
	router.GET("/v1/auth/otp/test-hint", handler.testOTPHint)

	req := httptest.NewRequest(http.MethodGet, "/v1/auth/otp/test-hint?email=ci@example.com", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("handler must refuse in production, got %d: %s", rec.Code, rec.Body.String())
	}
}
