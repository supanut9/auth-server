package domain

const (
	ClientStatusActive                   = "active"
	ClientTypePublic                     = "public"
	ClientTypeConfidential               = "confidential"
	AccountStatusActive                  = "active"
	AccessTokenStatusActive              = "active"
	AccessTokenStatusRevoked             = "revoked"
	RefreshTokenChainStatusActive        = "active"
	RefreshTokenChainStatusRevoked       = "revoked"
	SSOSessionStatusActive               = "active"
	SSOSessionStatusRevoked              = "revoked"
	AuthorizationStageLoginRequired      = "login_required"
	AuthorizationStageProviderRedirect   = "provider_redirect"
	AuthorizationStageOTPRequired        = "otp_required"
	AuthorizationStageConsentRequired    = "consent_required"
	AuthorizationStageAuthorizationReady = "authorization_ready"
	AuthorizationStageCompleted          = "completed"
	AuthorizationStageFailed             = "failed"
	AuthorizationStageExpired            = "expired"
)
