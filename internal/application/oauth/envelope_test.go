package oauth

import (
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"
)

func newTestSigner(t *testing.T) *EnvelopeSigner {
	t.Helper()
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatalf("secret: %v", err)
	}
	signer, err := NewEnvelopeSigner(secret, 10*time.Minute, NewMemoryJTIStore())
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return signer
}

func sampleEnvelope() Envelope {
	return Envelope{
		Provider:            "google",
		ClientID:            "trading-web",
		RedirectURI:         "https://trading.example.com/cb",
		Scope:               "openid email",
		State:               "client-state",
		Nonce:               "n123",
		CodeChallenge:       "abc",
		CodeChallengeMethod: "S256",
	}
}

func TestEnvelope_SignVerify(t *testing.T) {
	signer := newTestSigner(t)
	env := sampleEnvelope()

	token, err := signer.Sign(env)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	got, err := signer.Verify(token)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.ClientID != env.ClientID || got.State != env.State {
		t.Fatalf("round-trip mismatch: %+v vs %+v", got, env)
	}
}

func TestEnvelope_TamperedSignatureRejected(t *testing.T) {
	signer := newTestSigner(t)
	token, _ := signer.Sign(sampleEnvelope())
	parts := strings.SplitN(token, ".", 2)
	tampered := parts[0] + ".AAAA"
	_, err := signer.Verify(tampered)
	if err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("expected signature error, got %v", err)
	}
}

func TestEnvelope_TamperedPayloadRejected(t *testing.T) {
	signer := newTestSigner(t)
	token, _ := signer.Sign(sampleEnvelope())
	parts := strings.SplitN(token, ".", 2)
	// flip a single character in the encoded payload
	bytes := []byte(parts[0])
	bytes[0] ^= 0x01
	_, err := signer.Verify(string(bytes) + "." + parts[1])
	if err == nil {
		t.Fatalf("expected error for tampered payload")
	}
}

func TestEnvelope_ExpiredRejected(t *testing.T) {
	signer := newTestSigner(t)
	signer.now = func() time.Time { return time.Unix(1_700_000_000, 0).UTC() }
	token, _ := signer.Sign(sampleEnvelope())
	signer.now = func() time.Time { return time.Unix(1_700_000_000, 0).Add(11 * time.Minute).UTC() }
	_, err := signer.Verify(token)
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected expired error, got %v", err)
	}
}

func TestEnvelope_JTIReplayRejected(t *testing.T) {
	signer := newTestSigner(t)
	token, _ := signer.Sign(sampleEnvelope())
	if _, err := signer.Verify(token); err != nil {
		t.Fatalf("first verify: %v", err)
	}
	_, err := signer.Verify(token)
	if !errors.Is(err, ErrJTIExists) {
		t.Fatalf("expected ErrJTIExists, got %v", err)
	}
}

func TestEnvelope_ShortSecretRejected(t *testing.T) {
	if _, err := NewEnvelopeSigner([]byte("too short"), time.Minute, NewMemoryJTIStore()); err == nil {
		t.Fatalf("expected error for short secret")
	}
}

func TestEnvelope_MalformedToken(t *testing.T) {
	signer := newTestSigner(t)
	cases := []string{"", "no-dot", "two.three.parts.bad", "....", "onlydot."}
	for _, tc := range cases {
		t.Run(tc, func(t *testing.T) {
			if _, err := signer.Verify(tc); err == nil {
				t.Fatalf("expected error for %q", tc)
			}
		})
	}
}
