package http

import (
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// RateLimiter is an in-memory sliding-window rate limiter. Suitable for a
// single-process deployment; behind a load balancer you'd want a shared store
// (Redis). Each key tracks a ring of recent request timestamps; a new request
// is allowed iff the count within the window is under the limit.
type RateLimiter struct {
	mu       sync.Mutex
	window   time.Duration
	limit    int
	requests map[string][]time.Time
}

// NewRateLimiter constructs a limiter. window is the rolling window length,
// limit is the max requests permitted within it for a given key.
func NewRateLimiter(window time.Duration, limit int) *RateLimiter {
	return &RateLimiter{
		window:   window,
		limit:    limit,
		requests: make(map[string][]time.Time),
	}
}

// Allow returns (true, 0) if the request is allowed, otherwise (false,
// retryAfter) with the time until the oldest request in the window expires.
func (r *RateLimiter) Allow(key string, now time.Time) (bool, time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cutoff := now.Add(-r.window)
	hits := r.requests[key]
	// Drop expired entries from the front of the ring.
	idx := 0
	for idx < len(hits) && hits[idx].Before(cutoff) {
		idx++
	}
	hits = hits[idx:]
	if len(hits) >= r.limit {
		retryAfter := hits[0].Add(r.window).Sub(now)
		r.requests[key] = hits
		return false, retryAfter
	}
	r.requests[key] = append(hits, now)
	return true, 0
}

// Prune drops stale entries. Call periodically to keep memory bounded under
// low-traffic conditions where Allow doesn't get exercised often.
func (r *RateLimiter) Prune(now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cutoff := now.Add(-r.window)
	for key, hits := range r.requests {
		i := 0
		for i < len(hits) && hits[i].Before(cutoff) {
			i++
		}
		if i == len(hits) {
			delete(r.requests, key)
		} else if i > 0 {
			r.requests[key] = hits[i:]
		}
	}
}

// OTPRateLimitMiddleware caps OTP-endpoint hits per-IP. The limit is set high
// enough that legit users hitting Send/Verify/Resend a few times in a minute
// pass cleanly, but low enough that automated brute-force runs out quickly.
//
// We don't bind to email here because we don't parse the body — the email key
// is enforced inside the handler / identity service (challenge.AttemptCount
// already caps verify attempts at otpMaxAttempts per challenge).
func OTPRateLimitMiddleware(limiter *RateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		key := otpRateLimitKey(c)
		allowed, retryAfter := limiter.Allow(key, time.Now())
		if !allowed {
			seconds := int(retryAfter.Seconds())
			if seconds < 1 {
				seconds = 1
			}
			c.Header("Retry-After", strconv.Itoa(seconds))
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error":             "rate_limited",
				"error_description": "too many requests; try again in a moment",
			})
			return
		}
		c.Next()
	}
}

func otpRateLimitKey(c *gin.Context) string {
	// ClientIP() respects X-Forwarded-For / X-Real-IP per gin's TrustedProxies
	// config. In production set TrustedProxies to your CDN so we can't be
	// spoofed by clients setting their own XFF.
	ip := c.ClientIP()
	path := c.FullPath()
	return "otp:" + path + ":" + ip
}
