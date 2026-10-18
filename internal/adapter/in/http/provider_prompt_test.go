package http

import (
	"net/url"
	"testing"

	"github.com/supanut9/auth-server/internal/config"
)

// The provider step runs only from the login screen, so it must offer the provider's
// account chooser; otherwise signing in as a different Google/GitHub account is impossible.
func TestProviderAuthorizationURLAsksForAccountChooser(t *testing.T) {
	handler := Handler{cfg: config.Config{}}
	for _, provider := range []string{"google", "github"} {
		raw := handler.providerAuthorizationURLWithState(provider, "signed-state")
		u, err := url.Parse(raw)
		if err != nil || raw == "" {
			t.Fatalf("%s: bad url %q: %v", provider, raw, err)
		}
		if got := u.Query().Get("prompt"); got != "select_account" {
			t.Fatalf("%s: prompt = %q, want select_account", provider, got)
		}
		if got := u.Query().Get("state"); got != "signed-state" {
			t.Fatalf("%s: state = %q", provider, got)
		}
	}
}
