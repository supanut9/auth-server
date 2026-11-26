package mail

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// RenderOTPEmail reads the wall clock (time.Until), so cases are pinned by the
// remaining duration at render time rather than a fixed instant. Each value is
// at least 0.5s away from a whole minute, so test execution time cannot move
// the floor.
func TestGoldenOTPEmail(t *testing.T) {
	type renderCase struct {
		Name                string `json:"name"`
		AppName             string `json:"app_name"`
		Code                string `json:"code"`
		RemainingMsAtRender int64  `json:"remaining_ms_at_render"`
		MinutesShown        int    `json:"minutes_shown"`
		Subject             string `json:"subject"`
		Text                string `json:"text"`
		HTML                string `json:"html"`
		To                  string `json:"to"`
		From                string `json:"from"`
		MIME                string `json:"mime_message"`
	}
	inputs := []struct {
		name      string
		app       string
		code      string
		remaining time.Duration
		to        string
	}{
		{"ttl_10m_rendered_after_issue", "auth-server", "AbCd-_12", 10*time.Minute - 1*time.Millisecond, "user@example.com"},
		{"ttl_10m_plus_slack", "Interview Web", "x9Y8z7W6", 10*time.Minute + 500*time.Millisecond, "a.b+c@example.co.th"},
		{"one_hour", "Language", "QwErTy12", 60*time.Minute + 500*time.Millisecond, "user@example.com"},
		{"under_one_minute_clamps_to_1", "auth-server", "00000000", 30 * time.Second, "user@example.com"},
		{"already_expired_clamps_to_1", "auth-server", "--------", -5 * time.Minute, "user@example.com"},
		{"html_escaping", `A&B <"Co">`, `<b>&"`, 5*time.Minute + 500*time.Millisecond, "user@example.com"},
		{"non_ascii_app_name", "แอปเรียนภาษา", "ZZZZZZZZ", 2*time.Minute + 500*time.Millisecond, "ผู้ใช้@example.com"},
	}
	const from = "Auth Server <no-reply@auth.example.com>"
	var cases []renderCase
	for _, in := range inputs {
		subject, text, html := RenderOTPEmail(OTPEmailData{
			Code:      in.code,
			ExpiresAt: time.Now().Add(in.remaining),
			AppName:   in.app,
		})
		minutes := int(in.remaining.Minutes())
		if minutes < 1 {
			minutes = 1
		}
		if !strings.Contains(text, fmt.Sprintf("expires in %d minute(s)", minutes)) {
			t.Fatalf("%s: expected %d minute(s) in %q", in.name, minutes, text)
		}
		cases = append(cases, renderCase{
			Name: in.name, AppName: in.app, Code: in.code,
			RemainingMsAtRender: in.remaining.Milliseconds(), MinutesShown: minutes,
			Subject: subject, Text: text, HTML: html, To: in.to, From: from,
			MIME: buildMessage(from, Message{To: in.to, Subject: subject, Text: text, HTML: html}),
		})
	}
	goldenSection(t, "otp_email", "render", map[string]any{
		"description": "mail.RenderOTPEmail + smtp.go buildMessage. minutes = max(1, floor((expires_at - now_at_render) / 1 minute)) using the wall clock at render time. The identity service sets expires_at = now + OTP_CHALLENGE_TTL and renders a moment later, so the default 10m TTL always shows \"9 minute(s)\" (case ttl_10m_rendered_after_issue). App name and code are HTML-escaped in the HTML body only (& < > \" -> &amp; &lt; &gt; &#34;; ' is not escaped); subject and text are raw. The Subject header is NOT RFC 2047 encoded (raw UTF-8). MIME: CRLF header lines, fixed boundary, text part then HTML part, bodies inserted verbatim (text keeps LF line endings), each part followed by CRLF.",
		"cases":       cases,
	})

	textOnly := buildMessage(from, Message{To: "user@example.com", Subject: "Plain only", Text: "line1\nline2\n"})
	goldenSection(t, "otp_email", "mime_text_only", map[string]any{
		"description": "buildMessage without an HTML body: single text/plain part (not produced by the OTP flow today, kept for completeness).",
		"from":        from,
		"to":          "user@example.com",
		"subject":     "Plain only",
		"text":        "line1\nline2\n",
		"mime":        textOnly,
	})
}
