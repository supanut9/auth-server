# OTP Authentication Flow

## Overview

auth-server provides a password-less email OTP flow alongside the standard
Google and GitHub OAuth providers. A 6-digit code is emailed to the learner;
once verified, an SSO session is created and the OAuth authorization code flow
completes normally.

---

## End-to-End Flow

```
Browser                interview-web           auth-server            Email (Resend)
  │                         │                       │                      │
  │  GET /login             │                       │                      │
  │──────────────────────>  │                       │                      │
  │  [login page rendered]  │                       │                      │
  │  <──────────────────────│                       │                      │
  │                         │                       │                      │
  │  POST /v1/auth/otp/start (email + OAuth params) │                      │
  │─────────────────────────────────────────────>  │                      │
  │                         │                       │── SMTP send ───────> │
  │                         │                       │  (code, expires_in)  │
  │  {otp_challenge_id, email, expires_at}          │                      │
  │  <───────────────────────────────────────────── │                      │
  │                         │                       │                      │
  │  [user reads code from email]                   │                      │
  │                         │                       │                      │
  │  POST /v1/auth/otp/verify (challenge_id + code) │                      │
  │─────────────────────────────────────────────>  │                      │
  │                         │                       │ [sets SSO cookie]    │
  │  {account, redirect_to}                         │                      │
  │  <───────────────────────────────────────────── │                      │
  │                         │                       │                      │
  │  GET /auth/login (better-auth re-initiates)     │                      │
  │──────────────────────>  │                       │                      │
  │                         │──── authorize ──────> │                      │
  │                         │  [sees SSO cookie]    │                      │
  │                         │  [issues code]        │                      │
  │                         │ <──── code ────────── │                      │
  │                         │──── token exchange ──>│                      │
  │  [session cookie set]   │ <──── tokens ─────────│                      │
  │  <──────────────────────│                       │                      │
  │  [redirect to returnTo] │                       │                      │
```

### Step details

1. **POST `/v1/auth/otp/start`** — client sends `email` + OAuth params
   (`client_id`, `redirect_uri`, `scope`, `response_type`, `state`, `nonce`).
   auth-server validates the OAuth request, creates an `otp_challenges` record,
   and emails the code via the configured SMTP relay.

2. **SMTP delivery** — Resend (or any RFC 5321–compliant relay) delivers the
   HTML + plain-text email with the 6-digit code and expiry notice.

3. **POST `/v1/auth/otp/verify`** — client sends `otp_challenge_id`, `email`,
   `code` (same OAuth params). auth-server verifies the code hash, marks the
   challenge verified, upserts the account, creates an SSO session, and sets
   the `auth_sso_session` cookie on auth-server's domain.

4. **SSO cookie re-use** — interview-web redirects to `/auth/login`, which
   triggers better-auth's `signInWithOAuth2`. auth-server sees the active SSO
   session cookie, skips authentication, and issues an authorization code.

5. **Token exchange** — better-auth exchanges the code server-side (using the
   confidential client secret), creates the interview-web session cookie, and
   redirects to `returnTo`.

---

## Resend SMTP Environment Variables

Set these on the auth-server Vercel project (`supanut9-auth-server`):

| Variable | Value | Notes |
|---|---|---|
| `SMTP_HOST` | `smtp.resend.com` | Resend SMTP relay hostname |
| `SMTP_PORT` | `587` | STARTTLS port |
| `SMTP_USERNAME` | `resend` | Fixed literal for Resend SMTP |
| `SMTP_PASSWORD` | `<resend-api-key>` | API key from Resend dashboard |
| `SMTP_FROM` | `noreply@yourdomain.com` | Must be on a verified Resend domain |

### Operator prerequisites

1. Sign up at https://resend.com.
2. Add and verify your sending domain under **Resend → Domains**. Verification
   requires DNS records (SPF, DKIM, DMARC).
3. Create an API key under **Resend → API Keys** with at least **Sending
   Access** scope.
4. Set `SMTP_PASSWORD` to the API key value in Vercel.
5. Set `SMTP_FROM` to an address on the verified domain.

When `SMTP_HOST` is blank, auth-server boots without email delivery (OTP
challenges are created but the email is silently dropped). Use
`FIXED_OTP_CODE=123456` in non-production environments to bypass SMTP during
development.

---

## Test-Hint Shortcut (Non-Production Only)

`INT-244` adds `GET /v1/auth/otp/test-hint` so CI can retrieve the latest
active OTP challenge for an allowlisted email address without operator
intervention.

### Production refusal

The endpoint is **never mounted** when `APP_ENV=production`. The handler also
hard-refuses at the application level (defence-in-depth). Setting
`OTP_TEST_HINT_ALLOWLIST` in a production environment is rejected at startup.

### Enabling for CI

In non-production environments (e.g. `APP_ENV=staging` or `APP_ENV=development`):

1. Set `OTP_TEST_HINT_ALLOWLIST=ci-smoke@yourdomain.com` (comma-separated for
   multiple addresses).
2. Set `FIXED_OTP_CODE=123456` so auth-server always issues a known code.
   This avoids SMTP delivery entirely for CI.
3. The endpoint returns `{ otp_challenge_id, email, expires_at, code_hash_prefix }`.
   The `code_hash_prefix` is the first 8 characters of the stored code hash —
   it confirms the challenge is active without revealing the raw code over the
   wire. Since CI already knows the fixed code via `FIXED_OTP_CODE`, it can
   verify the challenge ID and proceed with OTP verify.

### CI cURL example (Lane E usage)

```bash
# 1. Start an OTP challenge
curl -s -X POST https://supanut9-auth-server.vercel.app/v1/auth/otp/start \
  -H 'Content-Type: application/json' \
  -d '{
    "response_type": "code",
    "client_id": "interview-web",
    "redirect_uri": "https://supanut9-interview-web.vercel.app/api/auth/oauth2/callback/auth-server",
    "scope": "openid email profile offline_access",
    "state": "ci-test-state-abc",
    "nonce": "ci-test-nonce-abc",
    "email": "ci-smoke@yourdomain.com"
  }'
# → {"otp_challenge_id":"<id>","email":"ci-smoke@yourdomain.com",...}

# 2. Retrieve the active challenge to confirm it was created (non-prod only)
CHALLENGE=$(curl -s \
  'https://supanut9-auth-server.vercel.app/v1/auth/otp/test-hint?email=ci-smoke@yourdomain.com')
OTP_CHALLENGE_ID=$(echo "$CHALLENGE" | jq -r .otp_challenge_id)

# 3. Verify the OTP — use the FIXED_OTP_CODE value known to CI
curl -s -X POST https://supanut9-auth-server.vercel.app/v1/auth/otp/verify \
  -H 'Content-Type: application/json' \
  -d "{
    \"response_type\": \"code\",
    \"client_id\": \"interview-web\",
    \"redirect_uri\": \"https://supanut9-interview-web.vercel.app/api/auth/oauth2/callback/auth-server\",
    \"scope\": \"openid email profile offline_access\",
    \"state\": \"ci-test-state-abc\",
    \"nonce\": \"ci-test-nonce-abc\",
    \"otp_challenge_id\": \"$OTP_CHALLENGE_ID\",
    \"email\": \"ci-smoke@yourdomain.com\",
    \"code\": \"123456\"
  }"
```

### Allowlisting a test mailbox

Add the email address to `OTP_TEST_HINT_ALLOWLIST` on the non-production Vercel
project. Separate multiple addresses with commas:

```
OTP_TEST_HINT_ALLOWLIST=ci-smoke@yourdomain.com,playwright@yourdomain.com
```

The test mailbox does not need to receive real email if `FIXED_OTP_CODE` is set.

---

## Rate Limiting

The OTP endpoints are protected by a shared per-IP rate limiter: **20 requests
per minute**. Application-level limits also apply:

| Limit | Value | Config env |
|---|---|---|
| Max verify attempts per challenge | 6 | `OTP_MAX_ATTEMPTS` |
| Max resends per challenge | 3 | `OTP_MAX_RESENDS` |
| Resend cooldown | 1 minute | `OTP_RESEND_COOLDOWN` |
| Challenge TTL | 10 minutes | `OTP_CHALLENGE_TTL` |

---

## Cross-references

- interview-web login UI: `interview-web/src/app/login/login-form.tsx`
- SMTP adapter: `auth-server/internal/adapter/out/mail/smtp.go`
- OTP email template: `auth-server/internal/adapter/out/mail/otp_template.go`
- OTP challenge repository: `auth-server/internal/adapter/out/persistence/otp_challenge_repository.go`
- Test-hint handler: `auth-server/internal/adapter/in/http/handlers_otp_test_hint.go`
- Test-hint tests: `auth-server/internal/adapter/in/http/handlers_otp_test_hint_test.go`
- Release-readiness runbook: `interview-web/docs/plan/interview-release-readiness-runbook.md`
- Root mirror: `docs/interview/otp-flow.md`
