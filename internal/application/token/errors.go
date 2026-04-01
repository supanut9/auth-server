package token

import "errors"

var (
	ErrRefreshTokenExpired        = errors.New("refresh token expired")
	ErrRefreshTokenRevoked        = errors.New("refresh token revoked")
	ErrRefreshTokenReuseDetected  = errors.New("refresh token reuse detected")
	ErrRefreshTokenClientMismatch = errors.New("refresh token client mismatch")
	ErrRefreshTokenChainInactive  = errors.New("refresh token chain inactive")
)
