//! OAuth protocol errors (`internal/application/oauth`).

use std::fmt;

use crate::ports::JtiStoreError;

/// OAuth / OIDC `error` codes emitted by the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OAuthErrorCode {
    InvalidRequest,
    InvalidClient,
    InvalidGrant,
    InvalidScope,
    InvalidToken,
    UnauthorizedClient,
    UnsupportedGrantType,
    UnsupportedResponseType,
    LoginRequired,
    ConsentRequired,
    ServerError,
}

impl OAuthErrorCode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::InvalidClient => "invalid_client",
            Self::InvalidGrant => "invalid_grant",
            Self::InvalidScope => "invalid_scope",
            Self::InvalidToken => "invalid_token",
            Self::UnauthorizedClient => "unauthorized_client",
            Self::UnsupportedGrantType => "unsupported_grant_type",
            Self::UnsupportedResponseType => "unsupported_response_type",
            Self::LoginRequired => "login_required",
            Self::ConsentRequired => "consent_required",
            Self::ServerError => "server_error",
        }
    }
}

impl fmt::Display for OAuthErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Authorization-request validation failure (Go `oauth.Error`).
///
/// Fatal errors happen before the redirect URI is trusted and must be rendered
/// by the server. Recoverable ones are redirected back to the client with
/// `?error=&error_description=`. auth-ui shows the description verbatim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[error("{}: {}", self.code(), self.description())]
pub enum ValidationError {
    // Fatal.
    ClientIdRequired,
    /// Any client lookup failure, including transport errors (as in Go).
    UnknownClient,
    ClientNotActive,
    RedirectUriRequired,
    RedirectUriNotRegistered,
    RedirectUriNotAbsolute,
    // Recoverable.
    ResponseTypeRequired,
    UnsupportedResponseType,
    StateRequired,
    ScopeRequired,
    ScopeNotAllowed,
    NonceRequired,
    CodeChallengeRequired,
    UnsupportedCodeChallengeMethod,
    PublicClientRequiresS256,
    CodeChallengeLength,
    CodeChallengeEncoding,
}

impl ValidationError {
    #[must_use]
    pub const fn code(self) -> OAuthErrorCode {
        match self {
            Self::UnknownClient | Self::ClientNotActive => OAuthErrorCode::InvalidClient,
            Self::UnsupportedResponseType => OAuthErrorCode::UnsupportedResponseType,
            Self::ScopeRequired | Self::ScopeNotAllowed => OAuthErrorCode::InvalidScope,
            Self::ClientIdRequired
            | Self::RedirectUriRequired
            | Self::RedirectUriNotRegistered
            | Self::RedirectUriNotAbsolute
            | Self::ResponseTypeRequired
            | Self::StateRequired
            | Self::NonceRequired
            | Self::CodeChallengeRequired
            | Self::UnsupportedCodeChallengeMethod
            | Self::PublicClientRequiresS256
            | Self::CodeChallengeLength
            | Self::CodeChallengeEncoding => OAuthErrorCode::InvalidRequest,
        }
    }

    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            Self::ClientIdRequired => "client_id is required",
            Self::UnknownClient => "client_id is unknown",
            Self::ClientNotActive => "client is not active",
            Self::RedirectUriRequired => "redirect_uri is required",
            Self::RedirectUriNotRegistered => "redirect_uri does not match a registered URI",
            Self::RedirectUriNotAbsolute => "redirect_uri must be an absolute URL",
            Self::ResponseTypeRequired => "response_type is required",
            Self::UnsupportedResponseType => "response_type must be code",
            Self::StateRequired => "state is required",
            Self::ScopeRequired => "scope is required",
            Self::ScopeNotAllowed => "requested scopes are not allowed for this client",
            Self::NonceRequired => "nonce is required for openid",
            Self::CodeChallengeRequired => "code_challenge is required for public clients",
            Self::UnsupportedCodeChallengeMethod => "unsupported code_challenge_method",
            Self::PublicClientRequiresS256 => {
                "public clients must use S256 for code_challenge_method"
            }
            Self::CodeChallengeLength => "code_challenge length must be 43\u{2013}128 characters",
            Self::CodeChallengeEncoding => {
                "code_challenge must be base64url-encoded without padding"
            }
        }
    }

    /// True once the redirect URI is trusted: report via redirect.
    #[must_use]
    pub const fn is_recoverable(self) -> bool {
        !self.is_fatal()
    }

    /// Go `oauth.IsFatal`: render server-side, never redirect.
    #[must_use]
    pub const fn is_fatal(self) -> bool {
        matches!(
            self,
            Self::ClientIdRequired
                | Self::UnknownClient
                | Self::ClientNotActive
                | Self::RedirectUriRequired
                | Self::RedirectUriNotRegistered
                | Self::RedirectUriNotAbsolute
        )
    }
}

/// Provider-state envelope failure. Rendered as `invalid_state` with this text
/// as `error_description`.
#[derive(Debug, thiserror::Error)]
pub enum EnvelopeError {
    #[error("envelope signer: secret must be at least 32 bytes, got {0}")]
    SecretTooShort(usize),
    #[error("envelope: malformed token")]
    MalformedToken,
    #[error("envelope: signature mismatch")]
    SignatureMismatch,
    /// Detail text comes from the base64 decoder.
    #[error("envelope: decode payload: {0}")]
    DecodePayload(String),
    /// Detail text comes from the JSON parser.
    #[error("envelope: parse claims: {0}")]
    ParseClaims(String),
    #[error("envelope: expired")]
    Expired,
    #[error("envelope: missing jti")]
    MissingJti,
    /// Replay (`oauth: jti replay`) or a store failure, shown verbatim.
    #[error(transparent)]
    Jti(#[from] JtiStoreError),
    #[error(transparent)]
    Random(#[from] crate::ports::RandomError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_errors_match_go() {
        use ValidationError as E;
        let cases = [
            (
                E::ClientIdRequired,
                "invalid_request",
                "client_id is required",
                true,
            ),
            (
                E::UnknownClient,
                "invalid_client",
                "client_id is unknown",
                true,
            ),
            (
                E::ClientNotActive,
                "invalid_client",
                "client is not active",
                true,
            ),
            (
                E::RedirectUriRequired,
                "invalid_request",
                "redirect_uri is required",
                true,
            ),
            (
                E::RedirectUriNotRegistered,
                "invalid_request",
                "redirect_uri does not match a registered URI",
                true,
            ),
            (
                E::RedirectUriNotAbsolute,
                "invalid_request",
                "redirect_uri must be an absolute URL",
                true,
            ),
            (
                E::ResponseTypeRequired,
                "invalid_request",
                "response_type is required",
                false,
            ),
            (
                E::UnsupportedResponseType,
                "unsupported_response_type",
                "response_type must be code",
                false,
            ),
            (
                E::StateRequired,
                "invalid_request",
                "state is required",
                false,
            ),
            (
                E::ScopeRequired,
                "invalid_scope",
                "scope is required",
                false,
            ),
            (
                E::ScopeNotAllowed,
                "invalid_scope",
                "requested scopes are not allowed for this client",
                false,
            ),
            (
                E::NonceRequired,
                "invalid_request",
                "nonce is required for openid",
                false,
            ),
            (
                E::CodeChallengeRequired,
                "invalid_request",
                "code_challenge is required for public clients",
                false,
            ),
            (
                E::UnsupportedCodeChallengeMethod,
                "invalid_request",
                "unsupported code_challenge_method",
                false,
            ),
            (
                E::PublicClientRequiresS256,
                "invalid_request",
                "public clients must use S256 for code_challenge_method",
                false,
            ),
            (
                E::CodeChallengeLength,
                "invalid_request",
                "code_challenge length must be 43–128 characters",
                false,
            ),
            (
                E::CodeChallengeEncoding,
                "invalid_request",
                "code_challenge must be base64url-encoded without padding",
                false,
            ),
        ];
        for (error, code, description, fatal) in cases {
            assert_eq!(error.code().as_str(), code, "{error:?}");
            assert_eq!(error.description(), description, "{error:?}");
            assert_eq!(error.is_fatal(), fatal, "{error:?}");
            assert_eq!(error.is_recoverable(), !fatal, "{error:?}");
            assert_eq!(error.to_string(), format!("{code}: {description}"));
        }
    }

    #[test]
    fn envelope_errors_match_go() {
        assert_eq!(
            EnvelopeError::MalformedToken.to_string(),
            "envelope: malformed token"
        );
        assert_eq!(
            EnvelopeError::SignatureMismatch.to_string(),
            "envelope: signature mismatch"
        );
        assert_eq!(EnvelopeError::Expired.to_string(), "envelope: expired");
        assert_eq!(
            EnvelopeError::MissingJti.to_string(),
            "envelope: missing jti"
        );
        assert_eq!(
            EnvelopeError::SecretTooShort(12).to_string(),
            "envelope signer: secret must be at least 32 bytes, got 12"
        );
        assert_eq!(
            EnvelopeError::from(JtiStoreError::Replay).to_string(),
            "oauth: jti replay"
        );
    }
}
