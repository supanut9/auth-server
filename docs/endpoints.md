# Endpoints

Phase-1 endpoint groups:

- discovery
  - `/.well-known/openid-configuration`
  - `/.well-known/jwks.json`
- health
  - `/healthz`
  - `/readyz`
- protocol
  - `/v1/oauth2/authorize`
  - `/v1/oauth2/token`
  - `/v1/oauth2/revoke`
  - `/v1/oauth2/introspect`
  - `/v1/oidc/userinfo`
- auth flow
  - `/v1/auth/requests/:request_id`
  - `/v1/auth/login/google`
  - `/v1/auth/login/github`
  - `/v1/auth/login/callback/google`
  - `/v1/auth/login/callback/github`
  - `/v1/auth/otp/start`
  - `/v1/auth/otp/verify`
  - `/v1/auth/otp/resend`
  - `/v1/auth/consent/accept`
  - `/v1/auth/consent/reject`
  - `/v1/auth/logout`
  - `/v1/auth/logout/global`

Implementation must follow RFC/OIDC-compatible behavior where the root docs require it.

Operational responses include `X-Request-Id`, and `/healthz` plus `/readyz` return the same `request_id` in JSON for smoke verification.

Refer to `../../docs/auth/phase-1-endpoints.md` for the authoritative phase-1 endpoint contract.
