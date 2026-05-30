package mail

import (
	"fmt"
	"strings"
	"time"
)

// OTPEmailData carries the values used to render the OTP email.
type OTPEmailData struct {
	// Code is the 6-digit (or generated) OTP code shown to the user.
	Code string
	// ExpiresAt is when the challenge expires, used to compute the "expires in N
	// minutes" line.
	ExpiresAt time.Time
	// AppName is shown in the email header, e.g. "Interview Web".
	AppName string
}

// RenderOTPEmail returns (subject, plaintext, html) for an OTP challenge email.
func RenderOTPEmail(data OTPEmailData) (subject, text, html string) {
	subject = fmt.Sprintf("Your %s verification code", data.AppName)

	minutesLeft := int(time.Until(data.ExpiresAt).Minutes())
	if minutesLeft < 1 {
		minutesLeft = 1
	}

	// Plain text body
	var tb strings.Builder
	tb.WriteString(fmt.Sprintf("Your %s verification code\n\n", data.AppName))
	tb.WriteString(fmt.Sprintf("    %s\n\n", data.Code))
	tb.WriteString(fmt.Sprintf("This code expires in %d minute(s).\n\n", minutesLeft))
	tb.WriteString("If you did not request this code you can safely ignore this email.\n")
	tb.WriteString("Do not share this code with anyone.\n")
	text = tb.String()

	// HTML body
	var hb strings.Builder
	hb.WriteString(`<!DOCTYPE html>`)
	hb.WriteString(`<html lang="en"><head><meta charset="UTF-8">`)
	hb.WriteString(`<meta name="viewport" content="width=device-width,initial-scale=1">`)
	hb.WriteString(`<title>Verification code</title></head>`)
	hb.WriteString(`<body style="margin:0;padding:0;background:#f5f5f5;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;">`)
	hb.WriteString(`<table width="100%" cellpadding="0" cellspacing="0" role="presentation">`)
	hb.WriteString(`<tr><td align="center" style="padding:40px 16px;">`)
	hb.WriteString(`<table width="560" cellpadding="0" cellspacing="0" role="presentation" style="max-width:560px;width:100%;background:#ffffff;border-radius:12px;box-shadow:0 2px 8px rgba(0,0,0,0.06);">`)
	hb.WriteString(`<tr><td style="padding:32px 40px 24px;border-bottom:1px solid #f0f0f0;">`)
	hb.WriteString(fmt.Sprintf(`<p style="margin:0;font-size:18px;font-weight:700;color:#1a1a1a;">%s</p>`, escapeHTML(data.AppName)))
	hb.WriteString(`</td></tr>`)
	hb.WriteString(`<tr><td style="padding:32px 40px 24px;">`)
	hb.WriteString(`<p style="margin:0 0 16px;font-size:15px;color:#444;">Your verification code is:</p>`)
	hb.WriteString(fmt.Sprintf(`<div style="display:inline-block;padding:18px 32px;background:#f8f4ff;border-radius:10px;font-size:36px;font-weight:700;letter-spacing:8px;color:#2d1b6e;font-family:'Courier New',Courier,monospace;">%s</div>`,
		escapeHTML(data.Code)))
	hb.WriteString(fmt.Sprintf(`<p style="margin:20px 0 0;font-size:13px;color:#888;">This code expires in <strong>%d minute(s)</strong>.</p>`,
		minutesLeft))
	hb.WriteString(`</td></tr>`)
	hb.WriteString(`<tr><td style="padding:0 40px 32px;">`)
	hb.WriteString(`<p style="margin:0;font-size:12px;color:#aaa;border-top:1px solid #f0f0f0;padding-top:20px;">`)
	hb.WriteString(`If you did not request this code, you can safely ignore this email. `)
	hb.WriteString(`Do not share this code with anyone.`)
	hb.WriteString(`</p></td></tr>`)
	hb.WriteString(`</table></td></tr></table>`)
	hb.WriteString(`</body></html>`)
	html = hb.String()

	return subject, text, html
}

func escapeHTML(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, `"`, "&#34;")
	return s
}
