package application

import (
	"github.com/supanut9/auth-server/internal/application/flow"
	"github.com/supanut9/auth-server/internal/application/identity"
	"github.com/supanut9/auth-server/internal/application/oauth"
	"github.com/supanut9/auth-server/internal/application/token"
	"github.com/supanut9/auth-server/internal/port"
)

type App struct {
	Flow     flow.Service
	Identity identity.Service
	Token    token.Service

	Accounts      port.AccountRepository
	Clients       port.OAuthClientRepository
	SSOSessions   port.SSOSessionRepository
	JWKS          port.JWKSProvider
	Verifier      port.JWTVerifier
	Providers     map[string]port.IdentityProvider
	RefreshChains port.RefreshTokenChainRepository
	RefreshTokens port.RefreshTokenRepository
	// OTPChallenges is exposed for the non-production test-hint endpoint
	// (INT-244). All other OTP operations go through Identity.
	OTPChallenges port.OTPChallengeRepository
	// Envelope signs OAuth `state` for external-provider bounces (Google/GitHub).
	// Nil-safe: handlers that don't yet use it can ignore.
	Envelope *oauth.EnvelopeSigner
}
