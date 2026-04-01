package application

import (
	"github.com/supanut9/auth-server/internal/application/flow"
	"github.com/supanut9/auth-server/internal/application/identity"
	"github.com/supanut9/auth-server/internal/application/token"
	"github.com/supanut9/auth-server/internal/port"
)

type App struct {
	Flow     flow.Service
	Identity identity.Service
	Token    token.Service

	Accounts    port.AccountRepository
	Clients     port.OAuthClientRepository
	SSOSessions port.SSOSessionRepository
	Requests    port.AuthorizationRequestRepository
	JWKS        port.JWKSProvider
	Providers   map[string]port.IdentityProvider
}
