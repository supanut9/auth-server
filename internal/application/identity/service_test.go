package identity

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/supanut9/auth-server/internal/application/flow"
	"github.com/supanut9/auth-server/internal/domain"
	"github.com/supanut9/auth-server/internal/port"
)

type fixedClock struct {
	now time.Time
}

func (c fixedClock) Now() time.Time {
	return c.now
}

type sequentialIDs struct {
	next int
}

func (g *sequentialIDs) NewID() (string, error) {
	g.next++
	return "id-" + time.Unix(int64(g.next), 0).UTC().Format("150405"), nil
}

type staticOTPCodeGenerator struct {
	code string
}

func (g staticOTPCodeGenerator) NewCode() (string, error) {
	if g.code == "" {
		return "123456", nil
	}
	return g.code, nil
}

type memoryAccountRepo struct {
	items map[string]domain.Account
	ids   *sequentialIDs
}

func (r *memoryAccountRepo) Create(_ context.Context, account domain.Account) (domain.Account, error) {
	if r.items == nil {
		r.items = map[string]domain.Account{}
	}
	if account.ID == "" && r.ids != nil {
		id, _ := r.ids.NewID()
		account.ID = id
	}
	r.items[account.ID] = account
	return account, nil
}

func (r *memoryAccountRepo) FindByID(_ context.Context, id string) (domain.Account, error) {
	account, ok := r.items[id]
	if !ok {
		return domain.Account{}, errors.New("not found")
	}
	return account, nil
}

func (r *memoryAccountRepo) FindByPrimaryVerifiedEmail(_ context.Context, email string) (domain.Account, error) {
	for _, account := range r.items {
		if account.PrimaryVerifiedEmail == email {
			return account, nil
		}
	}
	return domain.Account{}, errors.New("not found")
}

func (r *memoryAccountRepo) Update(_ context.Context, account domain.Account) (domain.Account, error) {
	if r.items == nil {
		r.items = map[string]domain.Account{}
	}
	r.items[account.ID] = account
	return account, nil
}

type memoryAccountProviderRepo struct {
	items map[string]domain.AccountProvider
	ids   *sequentialIDs
}

func (r *memoryAccountProviderRepo) key(provider string, providerAccountID string) string {
	return provider + "|" + providerAccountID
}

func (r *memoryAccountProviderRepo) Create(_ context.Context, provider domain.AccountProvider) (domain.AccountProvider, error) {
	if r.items == nil {
		r.items = map[string]domain.AccountProvider{}
	}
	if provider.ID == "" && r.ids != nil {
		id, _ := r.ids.NewID()
		provider.ID = id
	}
	r.items[r.key(provider.Provider, provider.ProviderAccountID)] = provider
	return provider, nil
}

func (r *memoryAccountProviderRepo) FindByProviderAccountID(_ context.Context, provider string, providerAccountID string) (domain.AccountProvider, error) {
	accountProvider, ok := r.items[r.key(provider, providerAccountID)]
	if !ok {
		return domain.AccountProvider{}, errors.New("not found")
	}
	return accountProvider, nil
}

func (r *memoryAccountProviderRepo) FindByAccountIDAndProvider(_ context.Context, accountID string, provider string) (domain.AccountProvider, error) {
	for _, accountProvider := range r.items {
		if accountProvider.AccountID == accountID && accountProvider.Provider == provider {
			return accountProvider, nil
		}
	}
	return domain.AccountProvider{}, errors.New("not found")
}

type memoryOTPRepo struct {
	items map[string]domain.OTPChallenge
	ids   *sequentialIDs
}

func (r *memoryOTPRepo) key(requestID string, email string) string {
	return requestID + "|" + email
}

func (r *memoryOTPRepo) Create(_ context.Context, challenge domain.OTPChallenge) (domain.OTPChallenge, error) {
	if r.items == nil {
		r.items = map[string]domain.OTPChallenge{}
	}
	if challenge.ID == "" && r.ids != nil {
		id, _ := r.ids.NewID()
		challenge.ID = id
	}
	if challenge.AuthorizationRequestID != nil {
		r.items[r.key(*challenge.AuthorizationRequestID, challenge.Email)] = challenge
	}
	return challenge, nil
}

func (r *memoryOTPRepo) FindActiveByRequestAndEmail(_ context.Context, requestID string, email string) (domain.OTPChallenge, error) {
	challenge, ok := r.items[r.key(requestID, email)]
	if !ok {
		return domain.OTPChallenge{}, errors.New("not found")
	}
	return challenge, nil
}

func (r *memoryOTPRepo) Update(_ context.Context, challenge domain.OTPChallenge) (domain.OTPChallenge, error) {
	if challenge.AuthorizationRequestID != nil {
		r.items[r.key(*challenge.AuthorizationRequestID, challenge.Email)] = challenge
	}
	return challenge, nil
}

type memoryMailSender struct {
	sent []port.MailMessage
}

func (s *memoryMailSender) Send(_ context.Context, message port.MailMessage) error {
	s.sent = append(s.sent, message)
	return nil
}

type memoryAuthorizationRequestRepo struct {
	items map[string]domain.AuthorizationRequest
	ids   *sequentialIDs
}

func (r *memoryAuthorizationRequestRepo) Create(_ context.Context, request domain.AuthorizationRequest) (domain.AuthorizationRequest, error) {
	if r.items == nil {
		r.items = map[string]domain.AuthorizationRequest{}
	}
	if request.ID == "" && r.ids != nil {
		id, _ := r.ids.NewID()
		request.ID = id
	}
	r.items[request.ID] = request
	return request, nil
}

func (r *memoryAuthorizationRequestRepo) FindByID(_ context.Context, id string) (domain.AuthorizationRequest, error) {
	request, ok := r.items[id]
	if !ok {
		return domain.AuthorizationRequest{}, errors.New("not found")
	}
	return request, nil
}

func (r *memoryAuthorizationRequestRepo) Update(_ context.Context, request domain.AuthorizationRequest) (domain.AuthorizationRequest, error) {
	if r.items == nil {
		r.items = map[string]domain.AuthorizationRequest{}
	}
	r.items[request.ID] = request
	return request, nil
}

type memoryAuthorizationCodeRepo struct{}

func (r *memoryAuthorizationCodeRepo) Create(_ context.Context, code domain.AuthorizationCode) (domain.AuthorizationCode, error) {
	return code, nil
}

func (r *memoryAuthorizationCodeRepo) FindByCodeHash(_ context.Context, codeHash string) (domain.AuthorizationCode, error) {
	return domain.AuthorizationCode{}, errors.New("not found")
}

func (r *memoryAuthorizationCodeRepo) Update(_ context.Context, code domain.AuthorizationCode) (domain.AuthorizationCode, error) {
	return code, nil
}

type memoryConsentRepo struct {
	items map[string]domain.ConsentGrant
}

func (r *memoryConsentRepo) key(accountID string, clientID string) string {
	return accountID + "|" + clientID
}

func (r *memoryConsentRepo) FindByAccountAndClient(_ context.Context, accountID string, clientID string) (domain.ConsentGrant, error) {
	grant, ok := r.items[r.key(accountID, clientID)]
	if !ok {
		return domain.ConsentGrant{}, errors.New("not found")
	}
	return grant, nil
}

func (r *memoryConsentRepo) Upsert(_ context.Context, grant domain.ConsentGrant) (domain.ConsentGrant, error) {
	if r.items == nil {
		r.items = map[string]domain.ConsentGrant{}
	}
	r.items[r.key(grant.AccountID, grant.ClientID)] = grant
	return grant, nil
}

type memorySSORepo struct {
	items map[string]domain.SSOSession
	ids   *sequentialIDs
}

func (r *memorySSORepo) Create(_ context.Context, session domain.SSOSession) (domain.SSOSession, error) {
	if r.items == nil {
		r.items = map[string]domain.SSOSession{}
	}
	if session.ID == "" && r.ids != nil {
		id, _ := r.ids.NewID()
		session.ID = id
	}
	r.items[session.ID] = session
	return session, nil
}

func (r *memorySSORepo) FindByID(_ context.Context, id string) (domain.SSOSession, error) {
	session, ok := r.items[id]
	if !ok {
		return domain.SSOSession{}, errors.New("not found")
	}
	return session, nil
}

func (r *memorySSORepo) Update(_ context.Context, session domain.SSOSession) (domain.SSOSession, error) {
	if r.items == nil {
		r.items = map[string]domain.SSOSession{}
	}
	r.items[session.ID] = session
	return session, nil
}

func (r *memorySSORepo) RevokeByID(_ context.Context, id string) error {
	session := r.items[id]
	now := time.Now().UTC()
	session.Status = domain.SSOSessionStatusRevoked
	session.RevokedAt = &now
	r.items[id] = session
	return nil
}

type memoryRefreshChainRepo struct {
	items map[string]domain.RefreshTokenChain
	ids   *sequentialIDs
}

func (r *memoryRefreshChainRepo) Create(_ context.Context, chain domain.RefreshTokenChain) (domain.RefreshTokenChain, error) {
	if r.items == nil {
		r.items = map[string]domain.RefreshTokenChain{}
	}
	if chain.ID == "" && r.ids != nil {
		id, _ := r.ids.NewID()
		chain.ID = id
	}
	r.items[chain.ID] = chain
	return chain, nil
}

func (r *memoryRefreshChainRepo) FindByID(_ context.Context, id string) (domain.RefreshTokenChain, error) {
	chain, ok := r.items[id]
	if !ok {
		return domain.RefreshTokenChain{}, errors.New("not found")
	}
	return chain, nil
}

func (r *memoryRefreshChainRepo) Update(_ context.Context, chain domain.RefreshTokenChain) (domain.RefreshTokenChain, error) {
	if r.items == nil {
		r.items = map[string]domain.RefreshTokenChain{}
	}
	r.items[chain.ID] = chain
	return chain, nil
}

func (r *memoryRefreshChainRepo) RevokeByID(_ context.Context, id string) error {
	chain := r.items[id]
	now := time.Now().UTC()
	chain.Status = domain.RefreshTokenChainStatusRevoked
	chain.RevokedAt = &now
	r.items[id] = chain
	return nil
}

type memoryRefreshTokenRepo struct{}

func (r *memoryRefreshTokenRepo) Create(_ context.Context, token domain.RefreshToken) (domain.RefreshToken, error) {
	return token, nil
}

func (r *memoryRefreshTokenRepo) FindByTokenHash(_ context.Context, tokenHash string) (domain.RefreshToken, error) {
	return domain.RefreshToken{}, errors.New("not found")
}

func (r *memoryRefreshTokenRepo) Update(_ context.Context, token domain.RefreshToken) (domain.RefreshToken, error) {
	return token, nil
}

func (r *memoryRefreshTokenRepo) RevokeByChainID(_ context.Context, chainID string) error {
	return nil
}

func newIdentityService(t *testing.T) (Service, *memoryMailSender, *memoryAuthorizationRequestRepo) {
	return newIdentityServiceWithConfig(t, Config{
		OTPChallengeTTL:   10 * time.Minute,
		OTPMaxAttempts:    6,
		OTPMaxResends:     3,
		OTPResendCooldown: time.Minute,
	})
}

func newIdentityServiceWithConfig(t *testing.T, cfg Config) (Service, *memoryMailSender, *memoryAuthorizationRequestRepo) {
	t.Helper()

	clock := fixedClock{now: time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)}
	ids := &sequentialIDs{}
	authRequests := &memoryAuthorizationRequestRepo{
		ids: ids,
		items: map[string]domain.AuthorizationRequest{
			"req-1": {
				ID:              "req-1",
				ClientID:        "trading-web",
				RedirectURI:     "https://client.example/callback",
				RequestedScopes: "openid profile trading.read",
				State:           "state-1",
				Stage:           domain.AuthorizationStageLoginRequired,
				ExpiresAt:       clock.now.Add(10 * time.Minute),
			},
		},
	}
	flowService := flow.NewService(
		flow.Config{
			AuthorizationRequestTTL: 10 * time.Minute,
			AuthorizationCodeTTL:    5 * time.Minute,
			SSOSessionTTL:           30 * 24 * time.Hour,
		},
		clock,
		ids,
		authRequests,
		&memoryAuthorizationCodeRepo{},
		&memoryConsentRepo{},
		&memorySSORepo{ids: ids},
		&memoryRefreshChainRepo{ids: ids},
		&memoryRefreshTokenRepo{},
	)
	mailSender := &memoryMailSender{}

	return NewService(
		cfg,
		clock,
		ids,
		staticOTPCodeGenerator{code: "123456"},
		&memoryAccountRepo{ids: ids},
		&memoryAccountProviderRepo{ids: ids},
		authRequests,
		&memoryOTPRepo{ids: ids},
		mailSender,
		flowService,
	), mailSender, authRequests
}

func TestProviderLoginCreatesAccountAndSession(t *testing.T) {
	t.Parallel()

	svc, _, requests := newIdentityService(t)
	request := requests.items["req-1"]
	request.Stage = domain.AuthorizationStageProviderRedirect
	requests.items["req-1"] = request

	account, providerLink, session, updated, err := svc.HandleProviderLogin(context.Background(), ProviderLoginRequest{
		RequestID:         "req-1",
		ProviderName:      "github",
		ProviderAccountID: "gh-1",
		Email:             "user@example.com",
		EmailVerified:     true,
		DisplayName:       "User",
	})
	if err != nil {
		t.Fatalf("provider login: %v", err)
	}
	if account.ID == "" || providerLink.ID == "" || session.ID == "" {
		t.Fatal("expected account, provider link, and sso session to be created")
	}
	if updated.Stage != domain.AuthorizationStageConsentRequired {
		t.Fatalf("expected consent_required after login, got %s", updated.Stage)
	}
	if got := requests.items["req-1"].PendingProviderName; got != "" {
		t.Fatalf("expected pending provider cleared, got %q", got)
	}
}

func TestProviderLoginRequiresEmailRecovery(t *testing.T) {
	t.Parallel()

	svc, _, requests := newIdentityService(t)
	request := requests.items["req-1"]
	request.Stage = domain.AuthorizationStageProviderRedirect
	requests.items["req-1"] = request
	_, _, _, request, err := svc.HandleProviderLogin(context.Background(), ProviderLoginRequest{
		RequestID:         "req-1",
		ProviderName:      "github",
		ProviderAccountID: "gh-1",
		Email:             "user@example.com",
		EmailVerified:     false,
		DisplayName:       "User",
	})
	if !errors.Is(err, ErrProviderEmailVerificationRequired) {
		t.Fatalf("expected email verification required, got %v", err)
	}
	if request.Stage != domain.AuthorizationStageOTPRequired {
		t.Fatalf("expected otp_required, got %s", request.Stage)
	}
	if request.PendingProviderName != "github" {
		t.Fatal("expected pending provider stored")
	}
}

func TestProviderLoginRejectsInvalidStage(t *testing.T) {
	t.Parallel()

	svc, _, _ := newIdentityService(t)
	_, _, _, _, err := svc.HandleProviderLogin(context.Background(), ProviderLoginRequest{
		RequestID:         "req-1",
		ProviderName:      "github",
		ProviderAccountID: "gh-1",
		Email:             "user@example.com",
		EmailVerified:     true,
		DisplayName:       "User",
	})
	if !errors.Is(err, ErrProviderLoginInvalidStage) {
		t.Fatalf("expected invalid stage, got %v", err)
	}
}

func TestOTPFlowLinksPendingProvider(t *testing.T) {
	t.Parallel()

	svc, mailSender, requests := newIdentityService(t)
	request := requests.items["req-1"]
	request.Stage = domain.AuthorizationStageProviderRedirect
	requests.items["req-1"] = request

	_, _, _, request, err := svc.HandleProviderLogin(context.Background(), ProviderLoginRequest{
		RequestID:         "req-1",
		ProviderName:      "github",
		ProviderAccountID: "gh-1",
		Email:             "user@example.com",
		EmailVerified:     false,
		DisplayName:       "User",
		AvatarURL:         "https://cdn.example/avatar.png",
	})
	if !errors.Is(err, ErrProviderEmailVerificationRequired) {
		t.Fatalf("expected email verification required, got %v", err)
	}

	challenge, err := svc.StartOTPChallenge(context.Background(), OTPStartRequest{RequestID: request.ID})
	if err != nil {
		t.Fatalf("start otp challenge: %v", err)
	}
	if challenge.Email != "user@example.com" {
		t.Fatalf("expected otp challenge email to be reused, got %s", challenge.Email)
	}
	if len(mailSender.sent) != 1 {
		t.Fatalf("expected one mail sent, got %d", len(mailSender.sent))
	}
	if !strings.Contains(mailSender.sent[0].Text, "123456") {
		t.Fatalf("expected mail to contain otp code, got %q", mailSender.sent[0].Text)
	}

	account, providerLink, session, updated, err := svc.VerifyOTPChallenge(context.Background(), OTPVerifyRequest{
		RequestID: request.ID,
		Email:     "user@example.com",
		Code:      "123456",
	})
	if err != nil {
		t.Fatalf("verify otp challenge: %v", err)
	}
	if account.ID == "" || providerLink.ID == "" || session.ID == "" {
		t.Fatal("expected account, provider link, and sso session to be created after otp verification")
	}
	if updated.Stage != domain.AuthorizationStageConsentRequired {
		t.Fatalf("expected consent_required after otp verify, got %s", updated.Stage)
	}
	if got := requests.items["req-1"].PendingProviderName; got != "" {
		t.Fatalf("expected pending provider cleared after otp verify, got %q", got)
	}
}

func TestOTPFlowThrottlesResend(t *testing.T) {
	t.Parallel()

	svc, mailSender, _ := newIdentityService(t)
	challenge, err := svc.StartOTPChallenge(context.Background(), OTPStartRequest{
		RequestID: "req-1",
		Email:     "user@example.com",
	})
	if err != nil {
		t.Fatalf("start otp challenge: %v", err)
	}
	if len(mailSender.sent) != 1 {
		t.Fatalf("expected one mail sent, got %d", len(mailSender.sent))
	}
	if _, err := svc.ResendOTPChallenge(context.Background(), OTPStartRequest{
		RequestID: "req-1",
		Email:     challenge.Email,
	}); !errors.Is(err, ErrOTPChallengeThrottled) {
		t.Fatalf("expected throttled resend, got %v", err)
	}
}

func TestOTPFlowStopsAfterMaxAttempts(t *testing.T) {
	t.Parallel()

	svc, _, _ := newIdentityServiceWithConfig(t, Config{
		OTPChallengeTTL:   10 * time.Minute,
		OTPMaxAttempts:    2,
		OTPMaxResends:     1,
		OTPResendCooldown: time.Minute,
	})

	if _, err := svc.StartOTPChallenge(context.Background(), OTPStartRequest{
		RequestID: "req-1",
		Email:     "user@example.com",
	}); err != nil {
		t.Fatalf("start otp challenge: %v", err)
	}

	_, _, _, _, err := svc.VerifyOTPChallenge(context.Background(), OTPVerifyRequest{
		RequestID: "req-1",
		Email:     "user@example.com",
		Code:      "000000",
	})
	if !errors.Is(err, ErrOTPChallengeInvalid) {
		t.Fatalf("expected invalid code, got %v", err)
	}

	_, _, _, _, err = svc.VerifyOTPChallenge(context.Background(), OTPVerifyRequest{
		RequestID: "req-1",
		Email:     "user@example.com",
		Code:      "000000",
	})
	if !errors.Is(err, ErrOTPChallengeTooManyAttempts) {
		t.Fatalf("expected too many attempts, got %v", err)
	}
}
