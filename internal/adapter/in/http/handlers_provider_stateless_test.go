package http

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/supanut9/auth-server/internal/adapter/out/persistence"
	"github.com/supanut9/auth-server/internal/adapter/out/persistence/schema"
	"github.com/supanut9/auth-server/internal/adapter/out/system"
	uuidadapter "github.com/supanut9/auth-server/internal/adapter/out/uuid"
	"github.com/supanut9/auth-server/internal/application"
	flowapp "github.com/supanut9/auth-server/internal/application/flow"
	identityapp "github.com/supanut9/auth-server/internal/application/identity"
	"github.com/supanut9/auth-server/internal/application/oauth"
	"github.com/supanut9/auth-server/internal/config"
	"github.com/supanut9/auth-server/internal/domain"
	"github.com/supanut9/auth-server/internal/port"
)

func TestProviderCallbackUsesAuthenticatedAccountWithExistingSSOCookie(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, tt := range []struct {
		name               string
		provider           string
		authenticatedGrant bool
	}{
		{name: "google with consent for both accounts", provider: "google", authenticatedGrant: true},
		{name: "github with consent only for cookie account", provider: "github"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			const (
				authUI      = "https://auth-ui.example"
				redirectURI = "https://client.example/callback"
				clientID    = "client"
				state       = "client-state"
				scope       = "email"
			)
			ctx := t.Context()
			db := newSupportTestDB(t)
			if err := db.AutoMigrate(&schema.AccountProviderModel{}, &schema.AuthorizationCodeModel{}); err != nil {
				t.Fatalf("prepare callback test tables: %v", err)
			}
			clock, ids := system.NewClock(), uuidadapter.NewGenerator()
			accounts := persistence.NewAccountRepository(db, ids, clock)
			clients := persistence.NewOAuthClientRepository(db, ids, clock)
			sessions := persistence.NewSSOSessionRepository(db, ids, clock)
			flow := flowapp.NewService(flowapp.Config{AuthorizationCodeTTL: time.Minute, SSOSessionTTL: time.Hour}, clock, ids,
				persistence.NewAuthorizationCodeRepository(db, ids, clock), persistence.NewConsentGrantRepository(db, ids, clock), sessions, nil, nil)
			identity := identityapp.NewService(identityapp.Config{}, clock, ids, nil, accounts,
				persistence.NewAccountProviderRepository(db, ids, clock), nil, nil, flow)
			signer, err := oauth.NewEnvelopeSigner(make([]byte, 32), time.Minute, oauth.NewMemoryJTIStore())
			if err != nil {
				t.Fatalf("create envelope signer: %v", err)
			}

			cookieAccount, err := accounts.Create(ctx, domain.Account{PrimaryVerifiedEmail: "alice@example.com"})
			if err != nil {
				t.Fatalf("create cookie account: %v", err)
			}
			authenticatedAccount, err := accounts.Create(ctx, domain.Account{PrimaryVerifiedEmail: "bob@example.com"})
			if err != nil {
				t.Fatalf("create authenticated account: %v", err)
			}
			oldSession, err := flow.StartSSOSession(ctx, cookieAccount.ID, "email_otp")
			if err != nil {
				t.Fatalf("create existing SSO session: %v", err)
			}
			if _, err := clients.Create(ctx, domain.OAuthClient{
				ClientID: clientID, ClientType: "confidential", RedirectURIs: []string{redirectURI}, AllowedScopes: scope,
			}); err != nil {
				t.Fatalf("create OAuth client: %v", err)
			}
			grantAccounts := []string{cookieAccount.ID}
			if tt.authenticatedGrant {
				grantAccounts = append(grantAccounts, authenticatedAccount.ID)
			}
			for _, accountID := range grantAccounts {
				if _, err := flow.UpsertConsent(ctx, flowapp.UpsertConsentRequest{
					AccountID: accountID, ClientID: clientID, Scopes: []string{scope},
				}); err != nil {
					t.Fatalf("grant consent: %v", err)
				}
			}

			provider := callbackTestProvider{profile: port.ProviderProfile{
				Name:          tt.provider,
				AccountID:     "provider-user",
				Email:         authenticatedAccount.PrimaryVerifiedEmail,
				EmailVerified: true,
			}}
			router := gin.New()
			RegisterRoutes(router, config.Config{AuthUIBaseURL: authUI}, db, application.App{
				Clients: clients, SSOSessions: sessions, Flow: flow, Identity: identity, Envelope: signer,
				Providers: map[string]port.IdentityProvider{tt.provider: provider},
			})
			envelope, err := signer.Sign(oauth.Envelope{
				Provider: tt.provider, ClientID: clientID, RedirectURI: redirectURI, Scope: scope, State: state, Prompt: "login",
			})
			if err != nil {
				t.Fatalf("sign provider state: %v", err)
			}
			query := url.Values{"state": {envelope}, "code": {"provider-code"}}
			req := httptest.NewRequest(http.MethodGet, "/v1/auth/login/callback/"+tt.provider+"?"+query.Encode(), nil)
			req.AddCookie(&http.Cookie{Name: ssoCookieName, Value: oldSession.ID})
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)

			if rec.Code != http.StatusFound {
				t.Fatalf("expected redirect, got %d: %s", rec.Code, rec.Body.String())
			}
			cookies := rec.Result().Cookies()
			if len(cookies) != 1 || cookies[0].Name != ssoCookieName || cookies[0].Value == oldSession.ID {
				t.Fatalf("expected a fresh SSO cookie, got %v", cookies)
			}
			newSession, err := sessions.FindByID(ctx, cookies[0].Value)
			if err != nil || newSession.AccountID != authenticatedAccount.ID {
				t.Fatalf("expected new session for account %q, got %q: %v", authenticatedAccount.ID, newSession.AccountID, err)
			}

			redirect, err := rec.Result().Location()
			if err != nil {
				t.Fatalf("read redirect location: %v", err)
			}
			params := redirect.Query()
			redirect.RawQuery = ""
			if params.Get("state") != state {
				t.Fatalf("redirect state = %q, want %q", params.Get("state"), state)
			}
			if tt.authenticatedGrant {
				if redirect.String() != redirectURI || params.Get("code") == "" {
					t.Fatalf("expected client redirect with a code, got %q", rec.Header().Get("Location"))
				}
				code, err := flow.ConsumeAuthorizationCode(ctx, flowapp.ConsumeAuthorizationCodeRequest{
					Code: params.Get("code"), ClientID: clientID, RedirectURI: redirectURI,
				})
				if err != nil {
					t.Fatalf("load issued authorization code: %v", err)
				}
				if code.AccountID != authenticatedAccount.ID {
					t.Errorf("code account = %q, want %q", code.AccountID, authenticatedAccount.ID)
				}
				if code.SSOSessionID == nil {
					t.Fatal("code has no SSO session ID")
				}
				if *code.SSOSessionID != newSession.ID {
					t.Errorf("code SSO session = %q, want %q", *code.SSOSessionID, newSession.ID)
				}
				return
			}

			if redirect.String() != authUI+"/consent" || params.Has("code") || params.Get("prompt") != "login" {
				t.Fatalf("expected consent redirect for authenticated account, got %q", rec.Header().Get("Location"))
			}
			var count int64
			if err := db.Model(&schema.AuthorizationCodeModel{}).Count(&count).Error; err != nil || count != 0 {
				t.Fatalf("expected no issued codes, got %d: %v", count, err)
			}
		})
	}
}

type callbackTestProvider struct {
	profile port.ProviderProfile
}

func (p callbackTestProvider) Name() string { return p.profile.Name }

func (p callbackTestProvider) ExchangeAuthorizationCode(context.Context, string, string) (port.ProviderProfile, error) {
	return p.profile, nil
}
