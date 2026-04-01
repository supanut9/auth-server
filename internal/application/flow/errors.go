package flow

import "errors"

var (
	ErrAuthorizationRequestExpired       = errors.New("authorization request expired")
	ErrAuthorizationRequestInvalidStage  = errors.New("authorization request invalid stage")
	ErrConsentRequired                   = errors.New("consent required")
	ErrAuthorizationCodeExpired          = errors.New("authorization code expired")
	ErrAuthorizationCodeAlreadyConsumed  = errors.New("authorization code already consumed")
	ErrAuthorizationCodeClientMismatch   = errors.New("authorization code client mismatch")
	ErrAuthorizationCodeRedirectMismatch = errors.New("authorization code redirect uri mismatch")
)
