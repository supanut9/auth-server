package provider

import "context"

type Profile struct {
	Name          string
	AccountID     string
	Email         string
	EmailVerified bool
	DisplayName   string
	AvatarURL     string
}

type OAuthProvider interface {
	Name() string
	ExchangeAuthorizationCode(ctx context.Context, code string, redirectURI string) (Profile, error)
}
