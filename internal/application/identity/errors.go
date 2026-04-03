package identity

import "errors"

var (
	ErrProviderEmailVerificationRequired = errors.New("provider email verification required")
	ErrProviderLoginInvalidStage         = errors.New("provider login invalid stage")
	ErrOTPChallengeExpired               = errors.New("otp challenge expired")
	ErrOTPChallengeInvalid               = errors.New("otp challenge invalid")
	ErrOTPChallengeNotFound              = errors.New("otp challenge not found")
	ErrOTPChallengeInvalidStage          = errors.New("otp challenge invalid stage")
	ErrOTPChallengeThrottled             = errors.New("otp challenge throttled")
	ErrOTPChallengeTooManyAttempts       = errors.New("otp challenge too many attempts")
	ErrOTPChallengeTooManyResends        = errors.New("otp challenge too many resends")
)
