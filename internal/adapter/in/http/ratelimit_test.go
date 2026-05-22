package http

import (
	"testing"
	"time"
)

func TestRateLimiter_AllowsUpToLimit(t *testing.T) {
	rl := NewRateLimiter(time.Minute, 3)
	now := time.Unix(1_700_000_000, 0)
	for i := 0; i < 3; i++ {
		ok, _ := rl.Allow("k", now)
		if !ok {
			t.Fatalf("request %d should be allowed", i+1)
		}
	}
	ok, retry := rl.Allow("k", now)
	if ok {
		t.Fatalf("4th request should be blocked")
	}
	if retry <= 0 || retry > time.Minute {
		t.Fatalf("retry-after out of range: %v", retry)
	}
}

func TestRateLimiter_WindowSlides(t *testing.T) {
	rl := NewRateLimiter(100*time.Millisecond, 2)
	now := time.Unix(1_700_000_000, 0)
	rl.Allow("k", now)
	rl.Allow("k", now)
	// After the window, old entries expire.
	later := now.Add(150 * time.Millisecond)
	ok, _ := rl.Allow("k", later)
	if !ok {
		t.Fatalf("should be allowed after window")
	}
}

func TestRateLimiter_KeysAreIsolated(t *testing.T) {
	rl := NewRateLimiter(time.Minute, 1)
	now := time.Unix(1_700_000_000, 0)
	if ok, _ := rl.Allow("a", now); !ok {
		t.Fatalf("first hit for 'a' should be allowed")
	}
	if ok, _ := rl.Allow("b", now); !ok {
		t.Fatalf("first hit for 'b' should be allowed")
	}
	if ok, _ := rl.Allow("a", now); ok {
		t.Fatalf("second hit for 'a' should be blocked")
	}
}

func TestRateLimiter_PruneDropsExpiredKeys(t *testing.T) {
	rl := NewRateLimiter(50*time.Millisecond, 5)
	now := time.Unix(1_700_000_000, 0)
	rl.Allow("k", now)
	rl.Prune(now.Add(time.Second))
	if _, ok := rl.requests["k"]; ok {
		t.Fatalf("expected expired key to be pruned")
	}
}
