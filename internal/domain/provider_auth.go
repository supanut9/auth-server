package domain

type PendingProviderProfile struct {
	Name          string
	AccountID     string
	Email         string
	EmailVerified bool
	DisplayName   string
	AvatarURL     string
}
