# Endpoints

The local server and the Vercel function serve the same HTTP routes.

| Group | Method | Path |
| --- | --- | --- |
| Discovery | `GET` | `/.well-known/openid-configuration` |
| Discovery | `GET` | `/.well-known/jwks.json` |
| Health | `GET` | `/healthz` |
| Health | `GET` | `/readyz` |
| Protocol | `GET` | `/v1/oauth2/authorize` |
| Protocol | `POST` | `/v1/oauth2/token` |
| Protocol | `POST` | `/v1/oauth2/revoke` |
| Protocol | `POST` | `/v1/oauth2/introspect` |
| Protocol | `GET` | `/v1/oidc/userinfo` |
| Client metadata | `GET` | `/v1/clients/:clientID/public-info` |
| Auth flow | `GET` | `/v1/auth/me` |
| Auth flow | `GET` | `/v1/auth/csrf` |
| Auth flow | `POST` | `/v1/auth/login/google`, `/v1/auth/login/github` |
| Auth flow | `GET` | `/v1/auth/login/callback/google`, `/v1/auth/login/callback/github` |
| Auth flow | `POST` | `/v1/auth/otp/start`, `/v1/auth/otp/verify`, `/v1/auth/otp/resend` |
| Auth flow | `POST` | `/v1/auth/consent/accept`, `/v1/auth/consent/reject` |
| Auth flow | `GET` | `/v1/auth/logout`, `/v1/auth/logout/global` |
| Support | `GET` | `/v1/support/accounts/:accountID` |
| Support | `POST` | `/v1/support/accounts/:accountID/sign-out` |
| Non-production | `GET` | `/dev/callback`, `/v1/auth/otp/test-hint` |

Pending authorization uses signed flow state. The originally planned `/v1/auth/requests/:request_id` endpoint is absent from the current router. Support routes require `Authorization: Bearer <SUPPORT_API_TOKEN>`.

Responses include `X-Request-Id`. `/healthz` and `/readyz` echo it as `request_id` in JSON. `/readyz` returns `503` when PostgreSQL is unreachable.

Token and introspection responses carry `Cache-Control: no-store` and `Pragma: no-cache` on success and error. Userinfo returns `WWW-Authenticate: Bearer` on a 401 with a missing token and `WWW-Authenticate: Bearer error="invalid_token"` on a 401 with an invalid token.

Authorization-code exchange checks PKCE before consuming the code. A wrong verifier returns `400 invalid_grant` with `error_description` set to `pkce validation failed`. The client can retry with the correct verifier until the code expires.

Token, revocation, and introspection require an active client. Empty client status counts as active. Inactive clients receive `401 {"error":"invalid_client"}`. Revocation returns an empty `200` for authenticated active clients, including requests for an unknown token, and `401` when client authentication fails.

ID tokens include `azp` with the client ID and include `sid` when the authorization code carries an SSO session ID. The ID token's `iss` matches discovery's `issuer` by trimming trailing slashes from `JWT_ISSUER`. Configurations without trailing slashes already use the same issuer. Access tokens continue to use the configured issuer verbatim.

JWT introspection and Userinfo require a JWT with the configured platform audience and a `scope` claim. ID tokens return `200 {"active":false}` from introspection and `401 invalid_token` from Userinfo. Client credentials access tokens can be active in introspection, including with an empty scope.

Refer to `../../docs/auth/phase-1-endpoints.md` in the parent workspace for the original phase-1 endpoint contract and [the cutover deviations](rust-port-deviations.md) for known compatibility differences.
