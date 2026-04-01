package persistence

import "time"

type AccountModel struct {
	ID                   string    `gorm:"type:uuid;primaryKey"`
	PrimaryVerifiedEmail string    `gorm:"size:320;not null;uniqueIndex"`
	DisplayName          string    `gorm:"size:255;not null"`
	AvatarURL            string    `gorm:"size:2048;not null;default:''"`
	Status               string    `gorm:"size:32;not null;index"`
	CreatedAt            time.Time `gorm:"not null"`
	UpdatedAt            time.Time `gorm:"not null"`
}

func (AccountModel) TableName() string {
	return "accounts"
}

type AccountProviderModel struct {
	ID                    string       `gorm:"type:uuid;primaryKey"`
	AccountID             string       `gorm:"type:uuid;not null;index"`
	Account               AccountModel `gorm:"foreignKey:AccountID;references:ID;constraint:OnUpdate:CASCADE,OnDelete:RESTRICT;"`
	Provider              string       `gorm:"size:64;not null;uniqueIndex:idx_provider_account"`
	ProviderAccountID     string       `gorm:"size:255;not null;uniqueIndex:idx_provider_account"`
	ProviderEmail         string       `gorm:"size:320;not null;default:''"`
	ProviderEmailVerified bool         `gorm:"not null;default:false"`
	ProfileName           string       `gorm:"size:255;not null;default:''"`
	ProfileAvatarURL      string       `gorm:"size:2048;not null;default:''"`
	CreatedAt             time.Time    `gorm:"not null"`
	UpdatedAt             time.Time    `gorm:"not null"`
}

func (AccountProviderModel) TableName() string {
	return "account_providers"
}

type OAuthClientModel struct {
	ID               string    `gorm:"type:uuid;primaryKey"`
	PublicClientID   string    `gorm:"column:client_id;size:128;not null;uniqueIndex:idx_oauth_clients_client_id"`
	ClientType       string    `gorm:"size:32;not null;index"`
	ClientSecretHash string    `gorm:"size:255;not null;default:''"`
	DisplayName      string    `gorm:"size:255;not null"`
	RedirectURIs     string    `gorm:"type:text;not null"`
	AllowedScopes    string    `gorm:"type:text;not null"`
	Status           string    `gorm:"size:32;not null;index"`
	CreatedAt        time.Time `gorm:"not null"`
	UpdatedAt        time.Time `gorm:"not null"`
}

func (OAuthClientModel) TableName() string {
	return "oauth_clients"
}

type AuthorizationRequestModel struct {
	ID                           string           `gorm:"type:uuid;primaryKey"`
	ClientID                     string           `gorm:"size:128;not null;index"`
	Client                       OAuthClientModel `gorm:"foreignKey:ClientID;references:PublicClientID;constraint:OnUpdate:CASCADE,OnDelete:RESTRICT;"`
	AccountID                    *string          `gorm:"type:uuid;index"`
	Account                      *AccountModel    `gorm:"foreignKey:AccountID;references:ID;constraint:OnUpdate:CASCADE,OnDelete:SET NULL;"`
	SSOSessionID                 *string          `gorm:"type:uuid;index"`
	SSOSession                   *SSOSessionModel `gorm:"foreignKey:SSOSessionID;references:ID;constraint:OnUpdate:CASCADE,OnDelete:SET NULL;"`
	RedirectURI                  string           `gorm:"size:2048;not null"`
	RequestedScopes              string           `gorm:"type:text;not null"`
	State                        string           `gorm:"size:512;not null"`
	Nonce                        *string          `gorm:"size:512"`
	PKCECodeChallenge            string           `gorm:"size:255;not null;default:''"`
	PKCECodeChallengeMethod      string           `gorm:"size:32;not null;default:''"`
	PendingProviderName          string           `gorm:"size:64;not null;default:''"`
	PendingProviderAccountID     string           `gorm:"size:255;not null;default:''"`
	PendingProviderEmail         string           `gorm:"size:320;not null;default:''"`
	PendingProviderEmailVerified bool             `gorm:"not null;default:false"`
	PendingProviderDisplayName   string           `gorm:"size:255;not null;default:''"`
	PendingProviderAvatarURL     string           `gorm:"size:2048;not null;default:''"`
	Stage                        string           `gorm:"size:64;not null;index"`
	ExpiresAt                    time.Time        `gorm:"not null;index"`
	CreatedAt                    time.Time        `gorm:"not null"`
	UpdatedAt                    time.Time        `gorm:"not null"`
}

func (AuthorizationRequestModel) TableName() string {
	return "authorization_requests"
}

type AuthorizationCodeModel struct {
	ID                      string                    `gorm:"type:uuid;primaryKey"`
	CodeHash                string                    `gorm:"size:255;not null;uniqueIndex"`
	AuthorizationRequestID  string                    `gorm:"type:uuid;not null;index"`
	AuthorizationRequest    AuthorizationRequestModel `gorm:"foreignKey:AuthorizationRequestID;references:ID;constraint:OnUpdate:CASCADE,OnDelete:RESTRICT;"`
	AccountID               string                    `gorm:"type:uuid;not null;index"`
	Account                 AccountModel              `gorm:"foreignKey:AccountID;references:ID;constraint:OnUpdate:CASCADE,OnDelete:RESTRICT;"`
	ClientID                string                    `gorm:"size:128;not null;index"`
	Client                  OAuthClientModel          `gorm:"foreignKey:ClientID;references:PublicClientID;constraint:OnUpdate:CASCADE,OnDelete:RESTRICT;"`
	SSOSessionID            *string                   `gorm:"type:uuid;index"`
	SSOSession              *SSOSessionModel          `gorm:"foreignKey:SSOSessionID;references:ID;constraint:OnUpdate:CASCADE,OnDelete:SET NULL;"`
	RedirectURI             string                    `gorm:"size:2048;not null"`
	GrantedScopes           string                    `gorm:"type:text;not null"`
	PKCECodeChallenge       string                    `gorm:"size:255;not null;default:''"`
	PKCECodeChallengeMethod string                    `gorm:"size:32;not null;default:''"`
	AuthTime                time.Time                 `gorm:"not null"`
	ExpiresAt               time.Time                 `gorm:"not null;index"`
	ConsumedAt              *time.Time
	CreatedAt               time.Time `gorm:"not null"`
}

func (AuthorizationCodeModel) TableName() string {
	return "authorization_codes"
}

type SSOSessionModel struct {
	ID              string       `gorm:"type:uuid;primaryKey"`
	AccountID       string       `gorm:"type:uuid;not null;index"`
	Account         AccountModel `gorm:"foreignKey:AccountID;references:ID;constraint:OnUpdate:CASCADE,OnDelete:RESTRICT;"`
	Status          string       `gorm:"size:32;not null;index"`
	LoginMethod     string       `gorm:"size:64;not null"`
	AuthenticatedAt time.Time    `gorm:"not null"`
	LastSeenAt      time.Time    `gorm:"not null"`
	ExpiresAt       time.Time    `gorm:"not null;index"`
	RevokedAt       *time.Time
	CreatedAt       time.Time `gorm:"not null"`
	UpdatedAt       time.Time `gorm:"not null"`
}

func (SSOSessionModel) TableName() string {
	return "sso_sessions"
}

type RefreshTokenChainModel struct {
	ID                string           `gorm:"type:uuid;primaryKey"`
	AccountID         string           `gorm:"type:uuid;not null;index"`
	Account           AccountModel     `gorm:"foreignKey:AccountID;references:ID;constraint:OnUpdate:CASCADE,OnDelete:RESTRICT;"`
	ClientID          string           `gorm:"size:128;not null;index"`
	Client            OAuthClientModel `gorm:"foreignKey:ClientID;references:PublicClientID;constraint:OnUpdate:CASCADE,OnDelete:RESTRICT;"`
	SSOSessionID      string           `gorm:"type:uuid;not null;index"`
	SSOSession        SSOSessionModel  `gorm:"foreignKey:SSOSessionID;references:ID;constraint:OnUpdate:CASCADE,OnDelete:RESTRICT;"`
	Scope             string           `gorm:"type:text;not null"`
	DeviceSessionID   string           `gorm:"size:255;not null;index"`
	Status            string           `gorm:"size:32;not null;index"`
	AbsoluteExpiresAt time.Time        `gorm:"not null;index"`
	InactiveExpiresAt time.Time        `gorm:"not null;index"`
	LastUsedAt        time.Time        `gorm:"not null"`
	RevokedAt         *time.Time
	CreatedAt         time.Time `gorm:"not null"`
	UpdatedAt         time.Time `gorm:"not null"`
}

func (RefreshTokenChainModel) TableName() string {
	return "refresh_token_chains"
}

type RefreshTokenModel struct {
	ID                  string                 `gorm:"type:uuid;primaryKey"`
	RefreshTokenChainID string                 `gorm:"type:uuid;not null;index"`
	RefreshTokenChain   RefreshTokenChainModel `gorm:"foreignKey:RefreshTokenChainID;references:ID;constraint:OnUpdate:CASCADE,OnDelete:RESTRICT;"`
	TokenHash           string                 `gorm:"size:255;not null;uniqueIndex"`
	IssuedAt            time.Time              `gorm:"not null"`
	ExpiresAt           time.Time              `gorm:"not null;index"`
	UsedAt              *time.Time
	ReplacedByTokenID   *string            `gorm:"type:uuid;index"`
	ReplacedByToken     *RefreshTokenModel `gorm:"foreignKey:ReplacedByTokenID;references:ID;constraint:OnUpdate:CASCADE,OnDelete:SET NULL;"`
	RevokedAt           *time.Time
}

func (RefreshTokenModel) TableName() string {
	return "refresh_tokens"
}

type ConsentGrantModel struct {
	ID            string           `gorm:"type:uuid;primaryKey"`
	AccountID     string           `gorm:"type:uuid;not null;index"`
	Account       AccountModel     `gorm:"foreignKey:AccountID;references:ID;constraint:OnUpdate:CASCADE,OnDelete:RESTRICT;"`
	ClientID      string           `gorm:"size:128;not null;index"`
	Client        OAuthClientModel `gorm:"foreignKey:ClientID;references:PublicClientID;constraint:OnUpdate:CASCADE,OnDelete:RESTRICT;"`
	GrantedScopes string           `gorm:"type:text;not null"`
	GrantedAt     time.Time        `gorm:"not null"`
	LastUsedAt    time.Time        `gorm:"not null"`
	RevokedAt     *time.Time
}

func (ConsentGrantModel) TableName() string {
	return "consent_grants"
}

type OTPChallengeModel struct {
	ID                     string                     `gorm:"type:uuid;primaryKey"`
	AuthorizationRequestID *string                    `gorm:"type:uuid;index"`
	AuthorizationRequest   *AuthorizationRequestModel `gorm:"foreignKey:AuthorizationRequestID;references:ID;constraint:OnUpdate:CASCADE,OnDelete:SET NULL;"`
	Email                  string                     `gorm:"size:320;not null;index"`
	Purpose                string                     `gorm:"size:64;not null;index"`
	CodeHash               string                     `gorm:"size:255;not null"`
	AttemptCount           int                        `gorm:"type:integer;not null;default:0"`
	ResendCount            int                        `gorm:"type:integer;not null;default:0"`
	ExpiresAt              time.Time                  `gorm:"not null;index"`
	VerifiedAt             *time.Time
	CreatedAt              time.Time `gorm:"not null"`
}

func (OTPChallengeModel) TableName() string {
	return "otp_challenges"
}

type AccessTokenModel struct {
	ID           string           `gorm:"type:uuid;primaryKey"`
	JTI          string           `gorm:"size:255;not null;uniqueIndex"`
	SID          string           `gorm:"column:sid;size:255;not null;index:idx_access_tokens_sid"`
	AccountID    *string          `gorm:"type:uuid;index"`
	Account      *AccountModel    `gorm:"foreignKey:AccountID;references:ID;constraint:OnUpdate:CASCADE,OnDelete:SET NULL;"`
	ClientID     string           `gorm:"size:128;not null;index"`
	Client       OAuthClientModel `gorm:"foreignKey:ClientID;references:PublicClientID;constraint:OnUpdate:CASCADE,OnDelete:RESTRICT;"`
	SSOSessionID *string          `gorm:"type:uuid;index"`
	SSOSession   *SSOSessionModel `gorm:"foreignKey:SSOSessionID;references:ID;constraint:OnUpdate:CASCADE,OnDelete:SET NULL;"`
	Audience     string           `gorm:"size:255;not null"`
	Scope        string           `gorm:"type:text;not null"`
	IssuedAt     time.Time        `gorm:"not null"`
	ExpiresAt    time.Time        `gorm:"not null;index"`
	Status       string           `gorm:"size:32;not null;index"`
	RevokedAt    *time.Time
	CreatedAt    time.Time `gorm:"not null"`
}

func (AccessTokenModel) TableName() string {
	return "access_tokens"
}

var schemaModels = []any{
	&AccountModel{},
	&AccountProviderModel{},
	&OAuthClientModel{},
	&AuthorizationRequestModel{},
	&AuthorizationCodeModel{},
	&SSOSessionModel{},
	&RefreshTokenChainModel{},
	&RefreshTokenModel{},
	&ConsentGrantModel{},
	&OTPChallengeModel{},
	&AccessTokenModel{},
}
