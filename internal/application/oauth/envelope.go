package oauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Envelope is a signed snapshot of the OAuth request handed to an external
// provider (Google/GitHub) as the `state` parameter. The provider echoes it back
// on callback unmodified; we verify the signature and trust the contents.
//
// This is the only place where flow state leaves auth-server. Inside our own
// surface we always re-validate from URL params + the client registry.
type Envelope struct {
	Provider            string `json:"provider"`
	ClientID            string `json:"client_id"`
	RedirectURI         string `json:"redirect_uri"`
	Scope               string `json:"scope"`
	State               string `json:"state"`
	Nonce               string `json:"nonce,omitempty"`
	CodeChallenge       string `json:"code_challenge,omitempty"`
	CodeChallengeMethod string `json:"code_challenge_method,omitempty"`
	Prompt              string `json:"prompt,omitempty"`
}

type envelopeClaims struct {
	Envelope
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
	JTI       string `json:"jti"`
}

// EnvelopeSigner produces and verifies envelope tokens. Uses HMAC-SHA256 over a
// compact "payload.signature" form (similar to JWT but without a header — we
// don't need algorithm negotiation, and the simpler format keeps the resulting
// state value shorter, which matters because some providers limit `state` to
// ~1KB).
//
// Replay protection is handled by JTIStore: each JTI is single-use across the
// signer's lifetime. The store rejects re-use even if a token is still within
// its expiry window.
type EnvelopeSigner struct {
	secret   []byte
	now      func() time.Time
	jtiStore JTIStore
	ttl      time.Duration
}

// JTIStore tracks already-consumed envelope JTIs so a stolen-and-replayed
// callback URL can't authenticate twice. Implementations are responsible for
// pruning expired entries — Insert returns ErrJTIExists on replay.
type JTIStore interface {
	Insert(jti string, expiresAt time.Time) error
}

// ErrJTIExists is returned by JTIStore implementations when a JTI is being
// re-used (i.e., replay attempt).
var ErrJTIExists = errors.New("oauth: jti replay")

// NewEnvelopeSigner constructs a signer. Secret must be at least 32 bytes;
// shorter secrets are accepted but a warning-shaped sentinel is returned.
func NewEnvelopeSigner(secret []byte, ttl time.Duration, jtiStore JTIStore) (*EnvelopeSigner, error) {
	if len(secret) < 32 {
		return nil, fmt.Errorf("envelope signer: secret must be at least 32 bytes, got %d", len(secret))
	}
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	return &EnvelopeSigner{
		secret:   secret,
		now:      time.Now,
		jtiStore: jtiStore,
		ttl:      ttl,
	}, nil
}

// Sign produces a token suitable for use as OAuth `state` on the wire. The
// returned string is opaque base64url(payload).base64url(hmac).
func (s *EnvelopeSigner) Sign(env Envelope) (string, error) {
	jti, err := randomJTI()
	if err != nil {
		return "", err
	}
	now := s.now().UTC()
	claims := envelopeClaims{
		Envelope:  env,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(s.ttl).Unix(),
		JTI:       jti,
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(encoded))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return encoded + "." + sig, nil
}

// Verify checks the signature, expiry, and JTI uniqueness, then returns the
// envelope. The JTI is consumed (recorded in the store) before returning, so a
// second call with the same token fails with ErrJTIExists.
func (s *EnvelopeSigner) Verify(token string) (Envelope, error) {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return Envelope{}, errors.New("envelope: malformed token")
	}
	encoded, sig := parts[0], parts[1]

	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(encoded))
	expected := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(expected), []byte(sig)) {
		return Envelope{}, errors.New("envelope: signature mismatch")
	}

	payload, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return Envelope{}, fmt.Errorf("envelope: decode payload: %w", err)
	}
	var claims envelopeClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return Envelope{}, fmt.Errorf("envelope: parse claims: %w", err)
	}

	now := s.now().UTC()
	if now.Unix() > claims.ExpiresAt {
		return Envelope{}, errors.New("envelope: expired")
	}
	if claims.JTI == "" {
		return Envelope{}, errors.New("envelope: missing jti")
	}

	if err := s.jtiStore.Insert(claims.JTI, time.Unix(claims.ExpiresAt, 0).UTC()); err != nil {
		return Envelope{}, err
	}

	return claims.Envelope, nil
}

func randomJTI() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// MemoryJTIStore is an in-memory JTIStore suitable for tests and single-process
// deployments. Production should use a DB-backed implementation behind the same
// interface to survive restarts and share state across replicas.
type MemoryJTIStore struct {
	store map[string]time.Time
}

// NewMemoryJTIStore constructs an empty in-memory store.
func NewMemoryJTIStore() *MemoryJTIStore {
	return &MemoryJTIStore{store: map[string]time.Time{}}
}

// Insert records the JTI, returning ErrJTIExists if already present (regardless
// of whether the previous record has expired — once seen, always seen, until
// pruned).
func (m *MemoryJTIStore) Insert(jti string, expiresAt time.Time) error {
	if _, ok := m.store[jti]; ok {
		return ErrJTIExists
	}
	m.store[jti] = expiresAt
	return nil
}

// Prune removes expired entries. Call on a timer in production deployments.
func (m *MemoryJTIStore) Prune(now time.Time) {
	for jti, exp := range m.store {
		if now.After(exp) {
			delete(m.store, jti)
		}
	}
}
