package identity

import "errors"

var (
	ErrProviderEmailVerificationRequired = errors.New("provider email verification required")
	ErrOTPChallengeExpired               = errors.New("otp challenge expired")
	ErrOTPChallengeInvalid               = errors.New("otp challenge invalid")
	ErrOTPChallengeNotFound              = errors.New("otp challenge not found")
)
