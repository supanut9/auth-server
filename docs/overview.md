# Overview

`auth-server` is the phase-1 authorization server.

It owns:

- OIDC discovery and JWKS
- OAuth/OIDC protocol endpoints
- provider integration for Google and GitHub
- Email OTP flow
- central SSO session management
- token issuance, refresh, revoke, and introspection

It does not own:

- rendered login pages
- rendered consent pages
- rendered OTP pages

Those belong to `auth-ui`.

Implementation must stay aligned with the root phase-1 docs.
