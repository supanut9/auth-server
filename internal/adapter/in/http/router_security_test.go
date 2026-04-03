package http

import (
	"testing"

	"github.com/supanut9/auth-server/internal/config"
)

func TestPostLogoutRedirectAcceptsSameOrigin(t *testing.T) {
	t.Parallel()

	handler := Handler{cfg: config.Config{AuthUIBaseURL: "https://auth-ui.example"}}
	candidate := "https://auth-ui.example/logout/signed-out"

	if got := handler.postLogoutRedirect(candidate); got != candidate {
		t.Fatalf("expected same-origin redirect to pass through, got %q", got)
	}
}

func TestPostLogoutRedirectRejectsCrossOrigin(t *testing.T) {
	t.Parallel()

	handler := Handler{cfg: config.Config{AuthUIBaseURL: "https://auth-ui.example"}}
	candidate := "https://evil.example/logout"

	if got := handler.postLogoutRedirect(candidate); got != "https://auth-ui.example/logout" {
		t.Fatalf("expected cross-origin redirect to fall back, got %q", got)
	}
}
