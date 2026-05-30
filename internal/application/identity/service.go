package identity

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/supanut9/auth-server/internal/adapter/out/mail"
	"github.com/supanut9/auth-server/internal/application/flow"
	"github.com/supanut9/auth-server/internal/domain"
	"github.com/supanut9/auth-server/internal/port"
)

type Config struct {
	OTPChallengeTTL   time.Duration
	OTPMaxAttempts    int
	OTPMaxResends     int
	OTPResendCooldown time.Duration
	// AppName is embedded in OTP email subjects and headers.
	// Defaults to "auth-server" when empty.
	AppName string
}

type Service struct {
	clock             port.Clock
	idGenerator       port.IDGenerator
	otpCodeGenerator  port.OTPCodeGenerator
	accounts          port.AccountRepository
	accountProviders  port.AccountProviderRepository
	otpChallenges     port.OTPChallengeRepository
	mailSender        port.MailSender
	flow              flow.Service
	otpChallengeTTL   time.Duration
	otpMaxAttempts    int
	otpMaxResends     int
	otpResendCooldown time.Duration
	appName           string
}

// ProviderLoginRequest is the internal input shape for resolving an account
// from a provider profile (used by HandleProviderLoginStateless). RequestID is
// vestigial and ignored — kept zero-valued to avoid breaking call sites.
type ProviderLoginRequest struct {
	RequestID         string
	ProviderName      string
	ProviderAccountID string
	Email             string
	EmailVerified     bool
	DisplayName       string
	AvatarURL         string
}

// ProviderLoginStatelessRequest is the input to the stateless provider-callback
// path. It carries only the provider-claimed identity; the OAuth request itself
// is reconstructed from the verified envelope state by the caller.
type ProviderLoginStatelessRequest struct {
	ProviderName      string
	ProviderAccountID string
	Email             string
	EmailVerified     bool
	DisplayName       string
	AvatarURL         string
}

// ProviderLoginStatelessResult is what the stateless callback handler needs to
// finish the flow: the authenticated account + a fresh SSO session.
type ProviderLoginStatelessResult struct {
	Account         domain.Account
	AccountProvider domain.AccountProvider
	Session         domain.SSOSession
}

// OTPStartStatelessRequest creates a new OTP challenge for a stateless flow.
// No AuthorizationRequest exists; the challenge stands alone, identified by
// its own ID (returned to the UI and carried in the URL until verify).
type OTPStartStatelessRequest struct {
	Email   string
	Purpose string
}

// OTPVerifyStatelessRequest verifies a stateless OTP challenge.
type OTPVerifyStatelessRequest struct {
	OTPChallengeID string
	Email          string
	Code           string
}

// OTPResendStatelessRequest re-issues an OTP code for an existing stateless
// challenge identified by its ID. Cooldown / max-resend rules apply identically
// to the legacy flow.
type OTPResendStatelessRequest struct {
	OTPChallengeID string
}

func NewService(
	cfg Config,
	clock port.Clock,
	idGenerator port.IDGenerator,
	otpCodeGenerator port.OTPCodeGenerator,
	accounts port.AccountRepository,
	accountProviders port.AccountProviderRepository,
	otpChallenges port.OTPChallengeRepository,
	mailSender port.MailSender,
	flowService flow.Service,
) Service {
	if otpCodeGenerator == nil {
		otpCodeGenerator = randomOTPCodeGenerator{}
	}

	appName := strings.TrimSpace(cfg.AppName)
	if appName == "" {
		appName = "auth-server"
	}

	return Service{
		clock:             clock,
		idGenerator:       idGenerator,
		otpCodeGenerator:  otpCodeGenerator,
		accounts:          accounts,
		accountProviders:  accountProviders,
		otpChallenges:     otpChallenges,
		mailSender:        mailSender,
		flow:              flowService,
		otpChallengeTTL:   cfg.OTPChallengeTTL,
		otpMaxAttempts:    positiveIntOrDefault(cfg.OTPMaxAttempts, 6),
		otpMaxResends:     positiveIntOrDefault(cfg.OTPMaxResends, 3),
		otpResendCooldown: durationOrDefault(cfg.OTPResendCooldown, time.Minute),
		appName:           appName,
	}
}

// HandleProviderLoginStateless is the stateless counterpart to
// HandleProviderLogin. It expects a fully-verified provider profile (email
// verified) and produces an authenticated SSO session. Caller is responsible
// for verifying the envelope JWT, reading OAuth params from URL, and deciding
// the post-auth redirect.
//
// Unverified provider emails (the rare path that today triggers an OTP recovery
// flow via PendingProvider* columns on AuthorizationRequest) return
// ErrProviderEmailVerificationRequired; the caller should redirect the user
// back to the login screen and prompt for email OTP from scratch.
func (s Service) HandleProviderLoginStateless(ctx context.Context, req ProviderLoginStatelessRequest) (ProviderLoginStatelessResult, error) {
	if !req.EmailVerified || strings.TrimSpace(req.Email) == "" {
		return ProviderLoginStatelessResult{}, ErrProviderEmailVerificationRequired
	}

	account, providerLink, err := s.resolveAccountAndProvider(ctx, ProviderLoginRequest{
		ProviderName:      req.ProviderName,
		ProviderAccountID: req.ProviderAccountID,
		Email:             req.Email,
		EmailVerified:     req.EmailVerified,
		DisplayName:       req.DisplayName,
		AvatarURL:         req.AvatarURL,
	})
	if err != nil {
		return ProviderLoginStatelessResult{}, err
	}

	session, err := s.flow.StartSSOSession(ctx, account.ID, req.ProviderName)
	if err != nil {
		return ProviderLoginStatelessResult{}, err
	}

	return ProviderLoginStatelessResult{
		Account:         account,
		AccountProvider: providerLink,
		Session:         session,
	}, nil
}

// StartOTPChallengeStateless creates a fresh OTP challenge that is NOT bound
// to any AuthorizationRequest. The returned challenge.ID is used by the UI as
// the otp_challenge_id URL param and as the lookup key on verify/resend.
func (s Service) StartOTPChallengeStateless(ctx context.Context, req OTPStartStatelessRequest) (domain.OTPChallenge, error) {
	email := strings.TrimSpace(req.Email)
	if email == "" {
		return domain.OTPChallenge{}, fmt.Errorf("otp email required")
	}

	codeValue, err := s.otpCodeGenerator.NewCode()
	if err != nil {
		return domain.OTPChallenge{}, err
	}
	_, codeHash, err := hashOTPCode(codeValue)
	if err != nil {
		return domain.OTPChallenge{}, err
	}

	now := s.clock.Now().UTC()
	purpose := strings.TrimSpace(req.Purpose)
	if purpose == "" {
		purpose = "login"
	}

	challenge, err := s.otpChallenges.Create(ctx, domain.OTPChallenge{
		AuthorizationRequestID: nil,
		Email:                  email,
		Purpose:                purpose,
		CodeHash:               codeHash,
		ExpiresAt:              now.Add(s.otpChallengeTTL),
		LastSentAt:             now,
		CreatedAt:              now,
	})
	if err != nil {
		return domain.OTPChallenge{}, err
	}

	if s.mailSender != nil {
		subject, text, html := mail.RenderOTPEmail(mail.OTPEmailData{
			Code:      codeValue,
			ExpiresAt: challenge.ExpiresAt,
			AppName:   s.appName,
		})
		_ = s.mailSender.Send(ctx, port.MailMessage{
			To:      email,
			Subject: subject,
			Text:    text,
			HTML:    html,
		})
	}

	return challenge, nil
}

// VerifyOTPChallengeStateless verifies a challenge by its ID + email + code.
// On success, an SSO session is created for the account and returned alongside
// the account/provider data. The challenge is marked verified to prevent reuse.
func (s Service) VerifyOTPChallengeStateless(ctx context.Context, req OTPVerifyStatelessRequest) (domain.Account, domain.SSOSession, error) {
	if strings.TrimSpace(req.OTPChallengeID) == "" {
		return domain.Account{}, domain.SSOSession{}, ErrOTPChallengeNotFound
	}

	challenge, err := s.otpChallenges.FindByID(ctx, req.OTPChallengeID)
	if err != nil {
		return domain.Account{}, domain.SSOSession{}, ErrOTPChallengeNotFound
	}
	if challenge.VerifiedAt != nil {
		return domain.Account{}, domain.SSOSession{}, ErrOTPChallengeInvalid
	}
	if !strings.EqualFold(strings.TrimSpace(challenge.Email), strings.TrimSpace(req.Email)) {
		return domain.Account{}, domain.SSOSession{}, ErrOTPChallengeNotFound
	}
	if challenge.AttemptCount >= s.otpMaxAttempts {
		return domain.Account{}, domain.SSOSession{}, ErrOTPChallengeTooManyAttempts
	}
	if s.clock.Now().UTC().After(challenge.ExpiresAt) {
		return domain.Account{}, domain.SSOSession{}, ErrOTPChallengeExpired
	}

	_, hash, err := hashOTPCode(req.Code)
	if err != nil {
		return domain.Account{}, domain.SSOSession{}, err
	}
	if hash != challenge.CodeHash {
		challenge.AttemptCount++
		_, _ = s.otpChallenges.Update(ctx, challenge)
		if challenge.AttemptCount >= s.otpMaxAttempts {
			return domain.Account{}, domain.SSOSession{}, ErrOTPChallengeTooManyAttempts
		}
		return domain.Account{}, domain.SSOSession{}, ErrOTPChallengeInvalid
	}

	// Find or create the account by verified email — stateless flow never
	// involves a pending-provider link, so there's nothing more to do.
	var account domain.Account
	if existing, err := s.accounts.FindByPrimaryVerifiedEmail(ctx, challenge.Email); err == nil {
		account = existing
	} else {
		account, err = s.accounts.Create(ctx, domain.Account{
			PrimaryVerifiedEmail: challenge.Email,
			DisplayName:          fallbackDisplayName("", challenge.Email),
			Status:               domain.AccountStatusActive,
		})
		if err != nil {
			return domain.Account{}, domain.SSOSession{}, err
		}
	}

	now := s.clock.Now().UTC()
	challenge.VerifiedAt = &now
	_, _ = s.otpChallenges.Update(ctx, challenge)

	session, err := s.flow.StartSSOSession(ctx, account.ID, "email_otp")
	if err != nil {
		return domain.Account{}, domain.SSOSession{}, err
	}

	return account, session, nil
}

// ResendOTPChallengeStateless re-issues an OTP code on an existing stateless
// challenge identified by ID. Standard cooldown / max-resend rules apply.
func (s Service) ResendOTPChallengeStateless(ctx context.Context, req OTPResendStatelessRequest) (domain.OTPChallenge, error) {
	if strings.TrimSpace(req.OTPChallengeID) == "" {
		return domain.OTPChallenge{}, ErrOTPChallengeNotFound
	}

	challenge, err := s.otpChallenges.FindByID(ctx, req.OTPChallengeID)
	if err != nil {
		return domain.OTPChallenge{}, ErrOTPChallengeNotFound
	}
	if challenge.VerifiedAt != nil {
		return domain.OTPChallenge{}, ErrOTPChallengeInvalid
	}
	if challenge.AttemptCount >= s.otpMaxAttempts {
		return domain.OTPChallenge{}, ErrOTPChallengeTooManyAttempts
	}
	if challenge.ResendCount >= s.otpMaxResends {
		return domain.OTPChallenge{}, ErrOTPChallengeTooManyResends
	}
	now := s.clock.Now().UTC()
	lastSentAt := challenge.LastSentAt
	if lastSentAt.IsZero() {
		lastSentAt = challenge.CreatedAt
	}
	if now.Before(lastSentAt.Add(s.otpResendCooldown)) {
		return domain.OTPChallenge{}, ErrOTPChallengeThrottled
	}

	codeValue, err := s.otpCodeGenerator.NewCode()
	if err != nil {
		return domain.OTPChallenge{}, err
	}
	_, codeHash, err := hashOTPCode(codeValue)
	if err != nil {
		return domain.OTPChallenge{}, err
	}

	challenge.ResendCount++
	challenge.CodeHash = codeHash
	challenge.ExpiresAt = now.Add(s.otpChallengeTTL)
	challenge.LastSentAt = now
	updated, err := s.otpChallenges.Update(ctx, challenge)
	if err != nil {
		return domain.OTPChallenge{}, err
	}

	if s.mailSender != nil {
		subject, text, html := mail.RenderOTPEmail(mail.OTPEmailData{
			Code:      codeValue,
			ExpiresAt: updated.ExpiresAt,
			AppName:   s.appName,
		})
		_ = s.mailSender.Send(ctx, port.MailMessage{
			To:      challenge.Email,
			Subject: subject,
			Text:    text,
			HTML:    html,
		})
	}

	return updated, nil
}

func (s Service) resolveAccountAndProvider(ctx context.Context, req ProviderLoginRequest) (domain.Account, domain.AccountProvider, error) {
	if existing, err := s.accountProviders.FindByProviderAccountID(ctx, req.ProviderName, req.ProviderAccountID); err == nil {
		account, err := s.accounts.FindByID(ctx, existing.AccountID)
		if err != nil {
			return domain.Account{}, domain.AccountProvider{}, err
		}
		return account, existing, nil
	}

	var account domain.Account
	if existingAccount, err := s.accounts.FindByPrimaryVerifiedEmail(ctx, req.Email); err == nil {
		account = existingAccount
	} else {
		account, err = s.accounts.Create(ctx, domain.Account{
			PrimaryVerifiedEmail: req.Email,
			DisplayName:          fallbackDisplayName(req.DisplayName, req.Email),
			AvatarURL:            req.AvatarURL,
			Status:               domain.AccountStatusActive,
		})
		if err != nil {
			return domain.Account{}, domain.AccountProvider{}, err
		}
	}

	providerLink, err := s.accountProviders.Create(ctx, domain.AccountProvider{
		AccountID:             account.ID,
		Provider:              req.ProviderName,
		ProviderAccountID:     req.ProviderAccountID,
		ProviderEmail:         req.Email,
		ProviderEmailVerified: req.EmailVerified,
		ProfileName:           req.DisplayName,
		ProfileAvatarURL:      req.AvatarURL,
	})
	if err != nil {
		return domain.Account{}, domain.AccountProvider{}, err
	}

	return account, providerLink, nil
}

func isOTPAllowedStage(stage string) bool {
	switch stage {
	case domain.AuthorizationStageLoginRequired,
		domain.AuthorizationStageProviderRedirect,
		domain.AuthorizationStageOTPRequired:
		return true
	default:
		return false
	}
}

func positiveIntOrDefault(value int, fallback int) int {
	if value <= 0 {
		return fallback
	}
	return value
}

func durationOrDefault(value time.Duration, fallback time.Duration) time.Duration {
	if value <= 0 {
		return fallback
	}
	return value
}

func fallbackDisplayName(name string, email string) string {
	if strings.TrimSpace(name) != "" {
		return name
	}
	at := strings.Index(email, "@")
	if at > 0 {
		return email[:at]
	}
	return email
}

func hashOTPCode(value string) (string, string, error) {
	if value == "" {
		return "", "", fmt.Errorf("empty otp code")
	}
	sum := sha256.Sum256([]byte(value))
	return value, base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

type randomOTPCodeGenerator struct{}

func (randomOTPCodeGenerator) NewCode() (string, error) {
	raw := make([]byte, 6)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
