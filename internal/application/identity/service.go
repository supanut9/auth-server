package identity

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/supanut9/auth-server/internal/application/flow"
	"github.com/supanut9/auth-server/internal/domain"
	"github.com/supanut9/auth-server/internal/port"
)

type Config struct {
	OTPChallengeTTL   time.Duration
	OTPMaxAttempts    int
	OTPMaxResends     int
	OTPResendCooldown time.Duration
}

type Service struct {
	clock                 port.Clock
	idGenerator           port.IDGenerator
	otpCodeGenerator      port.OTPCodeGenerator
	accounts              port.AccountRepository
	accountProviders      port.AccountProviderRepository
	authorizationRequests port.AuthorizationRequestRepository
	otpChallenges         port.OTPChallengeRepository
	mailSender            port.MailSender
	flow                  flow.Service
	otpChallengeTTL       time.Duration
	otpMaxAttempts        int
	otpMaxResends         int
	otpResendCooldown     time.Duration
}

type ProviderLoginRequest struct {
	RequestID         string
	ProviderName      string
	ProviderAccountID string
	Email             string
	EmailVerified     bool
	DisplayName       string
	AvatarURL         string
}

type OTPStartRequest struct {
	RequestID string
	Email     string
}

type OTPVerifyRequest struct {
	RequestID string
	Email     string
	Code      string
}

func NewService(
	cfg Config,
	clock port.Clock,
	idGenerator port.IDGenerator,
	otpCodeGenerator port.OTPCodeGenerator,
	accounts port.AccountRepository,
	accountProviders port.AccountProviderRepository,
	authorizationRequests port.AuthorizationRequestRepository,
	otpChallenges port.OTPChallengeRepository,
	mailSender port.MailSender,
	flowService flow.Service,
) Service {
	if otpCodeGenerator == nil {
		otpCodeGenerator = randomOTPCodeGenerator{}
	}

	return Service{
		clock:                 clock,
		idGenerator:           idGenerator,
		otpCodeGenerator:      otpCodeGenerator,
		accounts:              accounts,
		accountProviders:      accountProviders,
		authorizationRequests: authorizationRequests,
		otpChallenges:         otpChallenges,
		mailSender:            mailSender,
		flow:                  flowService,
		otpChallengeTTL:       cfg.OTPChallengeTTL,
		otpMaxAttempts:        positiveIntOrDefault(cfg.OTPMaxAttempts, 6),
		otpMaxResends:         positiveIntOrDefault(cfg.OTPMaxResends, 3),
		otpResendCooldown:     durationOrDefault(cfg.OTPResendCooldown, time.Minute),
	}
}

func (s Service) HandleProviderLogin(ctx context.Context, req ProviderLoginRequest) (domain.Account, domain.AccountProvider, domain.SSOSession, domain.AuthorizationRequest, error) {
	request, err := s.authorizationRequests.FindByID(ctx, req.RequestID)
	if err != nil {
		return domain.Account{}, domain.AccountProvider{}, domain.SSOSession{}, domain.AuthorizationRequest{}, err
	}
	if s.clock.Now().UTC().After(request.ExpiresAt) {
		return domain.Account{}, domain.AccountProvider{}, domain.SSOSession{}, domain.AuthorizationRequest{}, flow.ErrAuthorizationRequestExpired
	}
	if request.Stage != domain.AuthorizationStageProviderRedirect {
		return domain.Account{}, domain.AccountProvider{}, domain.SSOSession{}, domain.AuthorizationRequest{}, ErrProviderLoginInvalidStage
	}

	if !req.EmailVerified || strings.TrimSpace(req.Email) == "" {
		request.PendingProviderName = req.ProviderName
		request.PendingProviderAccountID = req.ProviderAccountID
		request.PendingProviderEmail = req.Email
		request.PendingProviderEmailVerified = req.EmailVerified
		request.PendingProviderDisplayName = req.DisplayName
		request.PendingProviderAvatarURL = req.AvatarURL
		request.Stage = domain.AuthorizationStageOTPRequired
		updated, updateErr := s.authorizationRequests.Update(ctx, request)
		if updateErr != nil {
			return domain.Account{}, domain.AccountProvider{}, domain.SSOSession{}, domain.AuthorizationRequest{}, updateErr
		}
		return domain.Account{}, domain.AccountProvider{}, domain.SSOSession{}, updated, ErrProviderEmailVerificationRequired
	}

	account, providerLink, err := s.resolveAccountAndProvider(ctx, req)
	if err != nil {
		return domain.Account{}, domain.AccountProvider{}, domain.SSOSession{}, domain.AuthorizationRequest{}, err
	}

	session, err := s.flow.StartSSOSession(ctx, account.ID, req.ProviderName)
	if err != nil {
		return domain.Account{}, domain.AccountProvider{}, domain.SSOSession{}, domain.AuthorizationRequest{}, err
	}

	updated, err := s.flow.AttachAuthenticatedSession(ctx, flow.AttachSessionRequest{
		RequestID:    req.RequestID,
		AccountID:    account.ID,
		SSOSessionID: session.ID,
	})
	if err != nil {
		return domain.Account{}, domain.AccountProvider{}, domain.SSOSession{}, domain.AuthorizationRequest{}, err
	}

	updated.PendingProviderName = ""
	updated.PendingProviderAccountID = ""
	updated.PendingProviderEmail = ""
	updated.PendingProviderEmailVerified = false
	updated.PendingProviderDisplayName = ""
	updated.PendingProviderAvatarURL = ""
	updated, err = s.authorizationRequests.Update(ctx, updated)
	if err != nil {
		return domain.Account{}, domain.AccountProvider{}, domain.SSOSession{}, domain.AuthorizationRequest{}, err
	}

	return account, providerLink, session, updated, nil
}

func (s Service) StartOTPChallenge(ctx context.Context, req OTPStartRequest) (domain.OTPChallenge, error) {
	request, err := s.authorizationRequests.FindByID(ctx, req.RequestID)
	if err != nil {
		return domain.OTPChallenge{}, err
	}
	if s.clock.Now().UTC().After(request.ExpiresAt) {
		return domain.OTPChallenge{}, flow.ErrAuthorizationRequestExpired
	}
	if !isOTPAllowedStage(request.Stage) {
		return domain.OTPChallenge{}, ErrOTPChallengeInvalidStage
	}

	email := strings.TrimSpace(req.Email)
	if email == "" {
		email = strings.TrimSpace(request.PendingProviderEmail)
	}
	if email == "" {
		return domain.OTPChallenge{}, fmt.Errorf("otp email required")
	}

	var existing *domain.OTPChallenge
	if activeChallenge, err := s.otpChallenges.FindActiveByRequestAndEmail(ctx, req.RequestID, email); err == nil {
		existing = &activeChallenge
	}

	challenge, codeValue, err := s.issueOTPChallenge(ctx, request, email, existing)
	if err != nil {
		return domain.OTPChallenge{}, err
	}

	request.Stage = domain.AuthorizationStageOTPRequired
	request.PendingProviderEmail = email
	if _, err := s.authorizationRequests.Update(ctx, request); err != nil {
		return domain.OTPChallenge{}, err
	}

	if s.mailSender != nil {
		_ = s.mailSender.Send(ctx, port.MailMessage{
			To:      email,
			Subject: "Your verification code",
			Text:    fmt.Sprintf("Your code is: %s", codeValue),
		})
	}

	return challenge, nil
}

func (s Service) VerifyOTPChallenge(ctx context.Context, req OTPVerifyRequest) (domain.Account, domain.AccountProvider, domain.SSOSession, domain.AuthorizationRequest, error) {
	request, err := s.authorizationRequests.FindByID(ctx, req.RequestID)
	if err != nil {
		return domain.Account{}, domain.AccountProvider{}, domain.SSOSession{}, domain.AuthorizationRequest{}, err
	}
	if s.clock.Now().UTC().After(request.ExpiresAt) {
		return domain.Account{}, domain.AccountProvider{}, domain.SSOSession{}, domain.AuthorizationRequest{}, flow.ErrAuthorizationRequestExpired
	}
	if request.Stage != domain.AuthorizationStageOTPRequired {
		return domain.Account{}, domain.AccountProvider{}, domain.SSOSession{}, domain.AuthorizationRequest{}, ErrOTPChallengeInvalidStage
	}

	challenge, err := s.otpChallenges.FindActiveByRequestAndEmail(ctx, req.RequestID, req.Email)
	if err != nil {
		return domain.Account{}, domain.AccountProvider{}, domain.SSOSession{}, domain.AuthorizationRequest{}, ErrOTPChallengeNotFound
	}
	if challenge.AttemptCount >= s.otpMaxAttempts {
		return domain.Account{}, domain.AccountProvider{}, domain.SSOSession{}, domain.AuthorizationRequest{}, ErrOTPChallengeTooManyAttempts
	}
	if s.clock.Now().UTC().After(challenge.ExpiresAt) {
		return domain.Account{}, domain.AccountProvider{}, domain.SSOSession{}, domain.AuthorizationRequest{}, ErrOTPChallengeExpired
	}

	_, hash, err := hashOTPCode(req.Code)
	if err != nil {
		return domain.Account{}, domain.AccountProvider{}, domain.SSOSession{}, domain.AuthorizationRequest{}, err
	}
	if hash != challenge.CodeHash {
		challenge.AttemptCount++
		_, _ = s.otpChallenges.Update(ctx, challenge)
		if challenge.AttemptCount >= s.otpMaxAttempts {
			return domain.Account{}, domain.AccountProvider{}, domain.SSOSession{}, domain.AuthorizationRequest{}, ErrOTPChallengeTooManyAttempts
		}
		return domain.Account{}, domain.AccountProvider{}, domain.SSOSession{}, domain.AuthorizationRequest{}, ErrOTPChallengeInvalid
	}

	account, providerLink, err := s.resolveAccountAfterOTP(ctx, request, req.Email)
	if err != nil {
		return domain.Account{}, domain.AccountProvider{}, domain.SSOSession{}, domain.AuthorizationRequest{}, err
	}

	now := s.clock.Now().UTC()
	challenge.VerifiedAt = &now
	_, _ = s.otpChallenges.Update(ctx, challenge)

	session, err := s.flow.StartSSOSession(ctx, account.ID, loginMethodFromRequest(request))
	if err != nil {
		return domain.Account{}, domain.AccountProvider{}, domain.SSOSession{}, domain.AuthorizationRequest{}, err
	}

	updated, err := s.flow.AttachAuthenticatedSession(ctx, flow.AttachSessionRequest{
		RequestID:    req.RequestID,
		AccountID:    account.ID,
		SSOSessionID: session.ID,
	})
	if err != nil {
		return domain.Account{}, domain.AccountProvider{}, domain.SSOSession{}, domain.AuthorizationRequest{}, err
	}

	updated.PendingProviderName = ""
	updated.PendingProviderAccountID = ""
	updated.PendingProviderEmail = ""
	updated.PendingProviderEmailVerified = false
	updated.PendingProviderDisplayName = ""
	updated.PendingProviderAvatarURL = ""
	updated, err = s.authorizationRequests.Update(ctx, updated)
	if err != nil {
		return domain.Account{}, domain.AccountProvider{}, domain.SSOSession{}, domain.AuthorizationRequest{}, err
	}

	return account, providerLink, session, updated, nil
}

func (s Service) ResendOTPChallenge(ctx context.Context, req OTPStartRequest) (domain.OTPChallenge, error) {
	request, err := s.authorizationRequests.FindByID(ctx, req.RequestID)
	if err != nil {
		return domain.OTPChallenge{}, err
	}
	if s.clock.Now().UTC().After(request.ExpiresAt) {
		return domain.OTPChallenge{}, flow.ErrAuthorizationRequestExpired
	}
	if !isOTPAllowedStage(request.Stage) {
		return domain.OTPChallenge{}, ErrOTPChallengeInvalidStage
	}

	email := strings.TrimSpace(req.Email)
	if email == "" {
		email = strings.TrimSpace(request.PendingProviderEmail)
	}
	if email == "" {
		return domain.OTPChallenge{}, fmt.Errorf("otp email required")
	}

	challenge, err := s.otpChallenges.FindActiveByRequestAndEmail(ctx, req.RequestID, email)
	if err != nil {
		return domain.OTPChallenge{}, ErrOTPChallengeNotFound
	}
	updated, codeValue, err := s.issueOTPChallenge(ctx, request, email, &challenge)
	if err != nil {
		return domain.OTPChallenge{}, err
	}

	if s.mailSender != nil {
		_ = s.mailSender.Send(ctx, port.MailMessage{
			To:      email,
			Subject: "Your verification code",
			Text:    fmt.Sprintf("Your code is: %s", codeValue),
		})
	}

	return updated, nil
}

func (s Service) issueOTPChallenge(ctx context.Context, request domain.AuthorizationRequest, email string, existing *domain.OTPChallenge) (domain.OTPChallenge, string, error) {
	now := s.clock.Now().UTC()
	if existing != nil {
		if existing.AttemptCount >= s.otpMaxAttempts {
			return domain.OTPChallenge{}, "", ErrOTPChallengeTooManyAttempts
		}
		if existing.ResendCount >= s.otpMaxResends {
			return domain.OTPChallenge{}, "", ErrOTPChallengeTooManyResends
		}
		lastSentAt := existing.LastSentAt
		if lastSentAt.IsZero() {
			lastSentAt = existing.CreatedAt
		}
		if now.Before(lastSentAt.Add(s.otpResendCooldown)) {
			return domain.OTPChallenge{}, "", ErrOTPChallengeThrottled
		}
	}

	codeValue, err := s.otpCodeGenerator.NewCode()
	if err != nil {
		return domain.OTPChallenge{}, "", err
	}
	_, codeHash, err := hashOTPCode(codeValue)
	if err != nil {
		return domain.OTPChallenge{}, "", err
	}

	if existing == nil {
		challenge := domain.OTPChallenge{
			AuthorizationRequestID: &request.ID,
			Email:                  email,
			Purpose:                otpPurpose(request),
			CodeHash:               codeHash,
			AttemptCount:           0,
			ResendCount:            0,
			ExpiresAt:              now.Add(s.otpChallengeTTL),
			LastSentAt:             now,
			CreatedAt:              now,
		}
		created, err := s.otpChallenges.Create(ctx, challenge)
		if err != nil {
			return domain.OTPChallenge{}, "", err
		}
		return created, codeValue, nil
	}

	existing.ResendCount++
	existing.CodeHash = codeHash
	existing.ExpiresAt = now.Add(s.otpChallengeTTL)
	existing.LastSentAt = now
	updated, err := s.otpChallenges.Update(ctx, *existing)
	if err != nil {
		return domain.OTPChallenge{}, "", err
	}
	return updated, codeValue, nil
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

func (s Service) resolveAccountAfterOTP(ctx context.Context, request domain.AuthorizationRequest, email string) (domain.Account, domain.AccountProvider, error) {
	var account domain.Account
	if existingAccount, err := s.accounts.FindByPrimaryVerifiedEmail(ctx, email); err == nil {
		account = existingAccount
	} else {
		account, err = s.accounts.Create(ctx, domain.Account{
			PrimaryVerifiedEmail: email,
			DisplayName:          fallbackDisplayName(request.PendingProviderDisplayName, email),
			AvatarURL:            request.PendingProviderAvatarURL,
			Status:               domain.AccountStatusActive,
		})
		if err != nil {
			return domain.Account{}, domain.AccountProvider{}, err
		}
	}

	if request.PendingProviderName != "" && request.PendingProviderAccountID != "" {
		if existing, err := s.accountProviders.FindByProviderAccountID(ctx, request.PendingProviderName, request.PendingProviderAccountID); err == nil {
			account, err := s.accounts.FindByID(ctx, existing.AccountID)
			if err != nil {
				return domain.Account{}, domain.AccountProvider{}, err
			}
			return account, existing, nil
		}

		providerLink, err := s.accountProviders.Create(ctx, domain.AccountProvider{
			AccountID:             account.ID,
			Provider:              request.PendingProviderName,
			ProviderAccountID:     request.PendingProviderAccountID,
			ProviderEmail:         email,
			ProviderEmailVerified: true,
			ProfileName:           request.PendingProviderDisplayName,
			ProfileAvatarURL:      request.PendingProviderAvatarURL,
		})
		if err != nil {
			return domain.Account{}, domain.AccountProvider{}, err
		}
		return account, providerLink, nil
	}

	return account, domain.AccountProvider{}, nil
}

func otpPurpose(request domain.AuthorizationRequest) string {
	if request.PendingProviderName != "" || request.PendingProviderEmail != "" {
		return "provider_email_recovery"
	}
	return "login"
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

func loginMethodFromRequest(request domain.AuthorizationRequest) string {
	if request.PendingProviderName != "" {
		return request.PendingProviderName
	}
	return "email_otp"
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
