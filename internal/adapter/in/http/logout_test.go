package http

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/mattn/go-sqlite3"

	"github.com/supanut9/auth-server/internal/adapter/out/persistence"
	"github.com/supanut9/auth-server/internal/adapter/out/persistence/schema"
	"github.com/supanut9/auth-server/internal/adapter/out/system"
	"github.com/supanut9/auth-server/internal/application"
	"github.com/supanut9/auth-server/internal/application/flow"
	"github.com/supanut9/auth-server/internal/config"
	"github.com/supanut9/auth-server/internal/domain"
)

func TestLogoutLocal(t *testing.T) {
	gin.SetMode(gin.TestMode)

	for _, tc := range []struct {
		name      string
		sessionID string
		chainID   string
		expired   bool
		revoked   bool
		failDB    string
	}{
		{name: "no cookie", chainID: "chain-1"},
		{name: "own chain", sessionID: "session-1", chainID: "chain-1", revoked: true},
		{name: "other session chain", sessionID: "session-1", chainID: "chain-2"},
		{name: "missing chain", sessionID: "session-1", chainID: "missing"},
		{name: "missing session", sessionID: "missing", chainID: "chain-1"},
		{name: "expired session", sessionID: "session-1", chainID: "chain-1", expired: true},
		{name: "redirect only", sessionID: "session-1", failDB: "session"},
		{name: "session lookup failure", sessionID: "session-1", chainID: "chain-1", failDB: "session"},
		{name: "chain lookup failure", sessionID: "session-1", chainID: "chain-1", failDB: "chain"},
		{name: "token revocation failure", sessionID: "session-1", chainID: "chain-1", failDB: "token"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := newSupportTestDB(t)
			sqlDB, err := db.DB()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = sqlDB.Close() })
			sqlDB.SetMaxOpenConns(1)
			conn, err := sqlDB.Conn(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			// Match the refresh token repository's PostgreSQL timestamp function.
			err = conn.Raw(func(driverConn any) error {
				return driverConn.(*sqlite3.SQLiteConn).RegisterFunc("now", func() string {
					return time.Now().UTC().Format(time.DateTime)
				}, false)
			})
			_ = conn.Close()
			if err != nil {
				t.Fatalf("register NOW: %v", err)
			}
			seedSupportFixture(t, db)

			expiresAt := time.Now().UTC().Add(time.Hour)
			if tc.expired {
				expiresAt = time.Now().UTC().Add(-time.Hour)
			}
			if err := db.Model(&schema.SSOSessionModel{}).Where("id = ?", "session-1").UpdateColumn("expires_at", expiresAt).Error; err != nil {
				t.Fatalf("set session expiry: %v", err)
			}

			var sessionsBefore []schema.SSOSessionModel
			if err := db.Order("id").Find(&sessionsBefore).Error; err != nil {
				t.Fatalf("load sessions before logout: %v", err)
			}

			sessionDB, chainDB, tokenDB := db, db, db
			switch tc.failDB {
			case "session":
				sessionDB = db.Table("missing_sessions")
			case "chain":
				chainDB = db.Table("missing_chains")
			case "token":
				tokenDB = db.Table("missing_tokens")
			}

			clock := system.NewClock()
			sessions := persistence.NewSSOSessionRepository(sessionDB, nil, clock)
			chains := persistence.NewRefreshTokenChainRepository(chainDB, nil, clock)
			tokens := persistence.NewRefreshTokenRepository(tokenDB, nil)
			app := application.App{
				Flow:        flow.NewService(flow.Config{}, clock, nil, nil, nil, sessions, chains, tokens),
				SSOSessions: sessions,
			}
			router := gin.New()
			RegisterRoutes(router, config.Config{AuthUIBaseURL: "https://auth-ui.example"}, db, app)

			const redirect = "https://auth-ui.example/signed-out"
			query := url.Values{"post_logout_redirect_uri": {redirect}}
			if tc.chainID != "" {
				query.Set("refresh_token_chain_id", tc.chainID)
			}
			req := httptest.NewRequest(http.MethodGet, "/v1/auth/logout?"+query.Encode(), nil)
			if tc.sessionID != "" {
				req.AddCookie(&http.Cookie{Name: ssoCookieName, Value: tc.sessionID})
			}
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)

			if tc.chainID != "" && tc.failDB != "" {
				if rec.Code != http.StatusInternalServerError || rec.Body.String() != `{"error":"server_error"}` {
					t.Fatalf("expected server error, got %d: %s", rec.Code, rec.Body.String())
				}
			} else if rec.Code != http.StatusFound || rec.Header().Get("Location") != redirect {
				t.Fatalf("expected 302 redirect to %q, got %d with location %q", redirect, rec.Code, rec.Header().Get("Location"))
			}
			if got := rec.Header().Values("Set-Cookie"); len(got) != 0 {
				t.Fatalf("expected no cookie changes, got %v", got)
			}

			var storedChains []schema.RefreshTokenChainModel
			if err := db.Find(&storedChains).Error; err != nil {
				t.Fatalf("load chains: %v", err)
			}
			for _, chain := range storedChains {
				wantStatus := domain.RefreshTokenChainStatusActive
				wantRevoked := tc.revoked && chain.ID == tc.chainID
				if wantRevoked {
					wantStatus = domain.RefreshTokenChainStatusRevoked
				}
				if chain.Status != wantStatus || (chain.RevokedAt != nil) != wantRevoked {
					t.Fatalf("chain %q has status %q and revoked_at %v, want status %q and revoked=%t", chain.ID, chain.Status, chain.RevokedAt, wantStatus, wantRevoked)
				}
			}

			var storedTokens []schema.RefreshTokenModel
			if err := db.Find(&storedTokens).Error; err != nil {
				t.Fatalf("load tokens: %v", err)
			}
			for _, token := range storedTokens {
				if want := tc.revoked && token.RefreshTokenChainID == tc.chainID; (token.RevokedAt != nil) != want {
					t.Fatalf("token %q has revoked_at %v, want revoked=%t", token.ID, token.RevokedAt, want)
				}
			}

			var sessionsAfter []schema.SSOSessionModel
			if err := db.Order("id").Find(&sessionsAfter).Error; err != nil {
				t.Fatalf("load sessions after logout: %v", err)
			}
			if !reflect.DeepEqual(sessionsAfter, sessionsBefore) {
				t.Fatal("local logout changed SSO sessions")
			}
		})
	}
}
