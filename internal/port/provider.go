package port

import (
	"context"
)

type ProviderProfile struct {
	Name          string
	AccountID     string
	Email         string
	EmailVerified bool
	DisplayName   string
	AvatarURL     string
}

type IdentityProvider interface {
	Name() string
	ExchangeAuthorizationCode(ctx context.Context, code string, redirectURI string) (ProviderProfile, error)
}
