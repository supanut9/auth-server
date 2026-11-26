//! Runtime configuration loading, at parity with `internal/config/config.go`.
//!
//! Same env var names, defaults, validation rules and error wording. An empty
//! value is treated as unset, as Go's `os.Getenv` does. Values are trimmed
//! only where Go trims them.

mod go;

use secrecy::{ExposeSecret, SecretString};
use time::Duration;

pub use go::{AtoiError, DurationError, ParseBoolError, atoi, parse_bool, parse_duration};

/// Service configuration.
#[derive(Debug, Clone)]
pub struct Config {
    pub app_name: String,
    pub app_env: String,
    pub http_addr: String,
    pub public_base_url: String,
    pub auth_ui_base_url: String,
    pub post_logout_redirect_allowlist: Vec<String>,
    pub database_url: SecretString,
    /// Parsed for parity but unused: Go never wired its Redis cache (plan D8).
    pub redis_url: SecretString,
    pub jwt_issuer: String,
    pub jwt_signing_alg: String,
    pub jwt_private_key_path: String,
    pub jwt_private_key_pem: SecretString,
    pub jwt_public_key_path: String,
    pub jwt_public_key_pem: String,
    pub sso_cookie_secure: bool,
    /// Lowercased and trimmed: `lax`, `strict`, `none` or empty.
    pub sso_cookie_same_site: String,
    pub sso_cookie_domain: String,
    pub google_client_id: String,
    pub google_client_secret: SecretString,
    pub google_redirect_url: String,
    pub github_client_id: String,
    pub github_client_secret: SecretString,
    pub github_redirect_url: String,
    pub smtp_host: String,
    pub smtp_port: String,
    pub smtp_username: String,
    pub smtp_password: SecretString,
    pub smtp_from: String,
    pub fixed_otp_code: String,
    /// Emails allowed to use `GET /v1/auth/otp/test-hint`. Refused in production.
    pub otp_test_hint_allowlist: Vec<String>,
    pub support_api_token: SecretString,
    pub platform_audience: String,
    pub access_token_ttl: Duration,
    pub id_token_ttl: Duration,
    pub refresh_absolute_ttl: Duration,
    pub refresh_inactive_ttl: Duration,
    /// Window in which a just-rotated refresh token may be replayed without
    /// counting as reuse.
    pub refresh_reuse_grace: Duration,
    pub otp_challenge_ttl: Duration,
    pub otp_max_attempts: i64,
    pub otp_max_resends: i64,
    pub otp_resend_cooldown: Duration,
    /// Parsed for parity but unused: the stateless flow has no stored
    /// authorization requests.
    pub authorization_request_ttl: Duration,
    pub authorization_code_ttl: Duration,
    pub sso_session_ttl: Duration,
    /// HMAC key for the provider `state` envelope. Production requires at least
    /// 32 bytes; elsewhere it falls back to a value derived from `PUBLIC_BASE_URL`.
    pub flow_envelope_secret: SecretString,
    pub flow_envelope_ttl: Duration,
}

/// Configuration error. Display text follows the Go messages.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    /// `missing required env: <what>`.
    #[error("missing required env: {0}")]
    Missing(&'static str),
    #[error("parse duration env {key}: {source}")]
    ParseDuration {
        key: &'static str,
        source: DurationError,
    },
    #[error("parse bool env {key}: {source}")]
    ParseBool {
        key: &'static str,
        source: ParseBoolError,
    },
    #[error("parse int env {key}: {source}")]
    ParseInt {
        key: &'static str,
        source: AtoiError,
    },
    #[error("invalid {key}: parse {}: {reason}", go::quote(.value))]
    InvalidUrl {
        key: &'static str,
        value: String,
        reason: String,
    },
    #[error("invalid {0}: must be an absolute URL")]
    RelativeUrl(&'static str),
    #[error("invalid SSO_COOKIE_SAME_SITE: must be lax, strict, or none")]
    InvalidSameSite,
    #[error("invalid cookie policy: SSO_COOKIE_SAME_SITE=none requires SSO_COOKIE_SECURE=true")]
    SameSiteNoneRequiresSecure,
    #[error("incomplete {0} provider config: set client id, secret, and redirect url together")]
    IncompleteProvider(&'static str),
    #[error("invalid SMTP_PORT: {0}")]
    InvalidSmtpPort(AtoiError),
    #[error("FIXED_OTP_CODE must not be set in production")]
    FixedOtpCodeInProduction,
    #[error("OTP_TEST_HINT_ALLOWLIST must not be set in production")]
    OtpTestHintAllowlistInProduction,
    #[error("invalid OTP_MAX_ATTEMPTS: must be greater than zero")]
    OtpMaxAttempts,
    #[error("invalid OTP_MAX_RESENDS: must be zero or greater")]
    OtpMaxResends,
    #[error("invalid OTP_RESEND_COOLDOWN: must be greater than zero")]
    OtpResendCooldown,
    #[error("FLOW_ENVELOPE_SECRET must be set to at least 32 bytes in production")]
    FlowEnvelopeSecretTooShort,
}

const MINUTE: Duration = Duration::minutes(1);
const HOUR: Duration = Duration::hours(1);

impl Config {
    /// Loads from the process environment.
    pub fn from_process_env() -> Result<Self, ConfigError> {
        Self::from_env(|key| {
            std::env::var_os(key).map(|value| value.to_string_lossy().into_owned())
        })
    }

    /// Loads from `get`, which returns the raw value of an env var.
    pub fn from_env(get: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let env = Env(get);

        let app_env = env.or("APP_ENV", "development");
        let public_base_url = env.required("PUBLIC_BASE_URL")?;
        let auth_ui_base_url = env.required("AUTH_UI_BASE_URL")?;
        let database_url = env.required("DATABASE_URL")?;
        let jwt_issuer = env.required("JWT_ISSUER")?;
        let access_token_ttl = env.duration("ACCESS_TOKEN_TTL", MINUTE * 10)?;
        let id_token_ttl = env.duration("ID_TOKEN_TTL", MINUTE * 10)?;
        let refresh_absolute_ttl = env.duration("REFRESH_TOKEN_ABSOLUTE_TTL", HOUR * 24 * 30)?;
        let refresh_inactive_ttl = env.duration("REFRESH_TOKEN_INACTIVE_TTL", HOUR * 24 * 7)?;
        let refresh_reuse_grace =
            env.duration("REFRESH_TOKEN_REUSE_GRACE", Duration::seconds(60))?;
        let otp_challenge_ttl = env.duration("OTP_CHALLENGE_TTL", MINUTE * 10)?;
        let otp_max_attempts = env.int("OTP_MAX_ATTEMPTS", 6)?;
        let otp_max_resends = env.int("OTP_MAX_RESENDS", 3)?;
        let otp_resend_cooldown = env.duration("OTP_RESEND_COOLDOWN", MINUTE)?;
        let authorization_request_ttl = env.duration("AUTHORIZATION_REQUEST_TTL", MINUTE * 10)?;
        let authorization_code_ttl = env.duration("AUTHORIZATION_CODE_TTL", MINUTE * 5)?;
        let sso_session_ttl = env.duration("SSO_SESSION_TTL", HOUR * 24 * 30)?;
        let flow_envelope_ttl = env.duration("FLOW_ENVELOPE_TTL", MINUTE * 10)?;

        let mut flow_envelope_secret = env.trimmed("FLOW_ENVELOPE_SECRET");
        if flow_envelope_secret.is_empty() && !is_production(&app_env) {
            flow_envelope_secret =
                format!("dev-flow-envelope-secret-{public_base_url}-min-32-bytes");
        }
        let sso_cookie_secure = env.boolean(
            "SSO_COOKIE_SECURE",
            default_sso_cookie_secure(&app_env, &public_base_url),
        )?;

        let config = Self {
            app_name: env.or("APP_NAME", "auth-server"),
            http_addr: env.or("HTTP_ADDR", ":8050"),
            post_logout_redirect_allowlist: env.list("POST_LOGOUT_REDIRECT_ALLOWLIST"),
            database_url: database_url.into(),
            redis_url: env.trimmed("REDIS_URL").into(),
            jwt_signing_alg: env.or("JWT_SIGNING_ALG", "RS256"),
            jwt_private_key_path: env.trimmed("JWT_PRIVATE_KEY_PATH"),
            jwt_private_key_pem: env.trimmed("JWT_PRIVATE_KEY_PEM").into(),
            jwt_public_key_path: env.trimmed("JWT_PUBLIC_KEY_PATH"),
            jwt_public_key_pem: env.trimmed("JWT_PUBLIC_KEY_PEM"),
            sso_cookie_secure,
            sso_cookie_same_site: env.or("SSO_COOKIE_SAME_SITE", "lax").trim().to_lowercase(),
            sso_cookie_domain: env.trimmed("SSO_COOKIE_DOMAIN"),
            google_client_id: env.trimmed("GOOGLE_CLIENT_ID"),
            google_client_secret: env.trimmed("GOOGLE_CLIENT_SECRET").into(),
            google_redirect_url: env.trimmed("GOOGLE_REDIRECT_URL"),
            github_client_id: env.trimmed("GITHUB_CLIENT_ID"),
            github_client_secret: env.trimmed("GITHUB_CLIENT_SECRET").into(),
            github_redirect_url: env.trimmed("GITHUB_REDIRECT_URL"),
            smtp_host: env.or("SMTP_HOST", ""),
            smtp_port: env.or("SMTP_PORT", "587"),
            smtp_username: env.or("SMTP_USERNAME", ""),
            smtp_password: env.or("SMTP_PASSWORD", "").into(),
            smtp_from: env.or("SMTP_FROM", ""),
            fixed_otp_code: env.trimmed("FIXED_OTP_CODE"),
            otp_test_hint_allowlist: env.list("OTP_TEST_HINT_ALLOWLIST"),
            support_api_token: env
                .or("SUPPORT_API_TOKEN", default_support_api_token(&app_env))
                .into(),
            platform_audience: env.or("PLATFORM_AUDIENCE", "platform-api"),
            app_env,
            public_base_url,
            auth_ui_base_url,
            jwt_issuer,
            access_token_ttl,
            id_token_ttl,
            refresh_absolute_ttl,
            refresh_inactive_ttl,
            refresh_reuse_grace,
            otp_challenge_ttl,
            otp_max_attempts,
            otp_max_resends,
            otp_resend_cooldown,
            authorization_request_ttl,
            authorization_code_ttl,
            sso_session_ttl,
            flow_envelope_secret: flow_envelope_secret.into(),
            flow_envelope_ttl,
        };
        config.validate()?;
        Ok(config)
    }

    /// Go `Config.Validate`, in the same check order.
    pub fn validate(&self) -> Result<(), ConfigError> {
        validate_absolute_url("PUBLIC_BASE_URL", &self.public_base_url)?;
        validate_absolute_url("AUTH_UI_BASE_URL", &self.auth_ui_base_url)?;
        for candidate in &self.post_logout_redirect_allowlist {
            validate_absolute_url("POST_LOGOUT_REDIRECT_ALLOWLIST", candidate)?;
        }
        validate_absolute_url("JWT_ISSUER", &self.jwt_issuer)?;
        self.validate_cookie_policy()?;
        self.validate_jwt_key_sources()?;
        validate_provider_group(
            "GOOGLE",
            [
                &self.google_client_id,
                self.google_client_secret.expose_secret(),
                &self.google_redirect_url,
            ],
        )?;
        validate_provider_group(
            "GITHUB",
            [
                &self.github_client_id,
                self.github_client_secret.expose_secret(),
                &self.github_redirect_url,
            ],
        )?;

        if !self.smtp_host.trim().is_empty() {
            if self.smtp_from.trim().is_empty() {
                return Err(ConfigError::Missing("SMTP_FROM when SMTP_HOST is set"));
            }
            atoi(self.smtp_port.trim()).map_err(ConfigError::InvalidSmtpPort)?;
        }
        if !self.fixed_otp_code.is_empty() && self.is_production() {
            return Err(ConfigError::FixedOtpCodeInProduction);
        }
        if !self.otp_test_hint_allowlist.is_empty() && self.is_production() {
            return Err(ConfigError::OtpTestHintAllowlistInProduction);
        }
        if self.support_api_token.expose_secret().trim().is_empty() {
            return Err(ConfigError::Missing("SUPPORT_API_TOKEN"));
        }

        if self.otp_max_attempts <= 0 {
            return Err(ConfigError::OtpMaxAttempts);
        }
        if self.otp_max_resends < 0 {
            return Err(ConfigError::OtpMaxResends);
        }
        if self.otp_resend_cooldown <= Duration::ZERO {
            return Err(ConfigError::OtpResendCooldown);
        }
        if self.is_production() && self.flow_envelope_secret.expose_secret().trim().len() < 32 {
            return Err(ConfigError::FlowEnvelopeSecretTooShort);
        }
        Ok(())
    }

    /// `APP_ENV` equals `production`, ignoring case.
    #[must_use]
    pub fn is_production(&self) -> bool {
        is_production(&self.app_env)
    }

    fn validate_cookie_policy(&self) -> Result<(), ConfigError> {
        match self.sso_cookie_same_site.as_str() {
            "" | "lax" | "strict" | "none" => {}
            _ => return Err(ConfigError::InvalidSameSite),
        }
        if self.sso_cookie_same_site == "none" && !self.sso_cookie_secure {
            return Err(ConfigError::SameSiteNoneRequiresSecure);
        }
        Ok(())
    }

    fn validate_jwt_key_sources(&self) -> Result<(), ConfigError> {
        if self.jwt_private_key_path.trim().is_empty()
            && self.jwt_private_key_pem.expose_secret().trim().is_empty()
        {
            return Err(ConfigError::Missing(
                "JWT_PRIVATE_KEY_PATH or JWT_PRIVATE_KEY_PEM",
            ));
        }
        if self.jwt_public_key_path.trim().is_empty() && self.jwt_public_key_pem.trim().is_empty() {
            return Err(ConfigError::Missing(
                "JWT_PUBLIC_KEY_PATH or JWT_PUBLIC_KEY_PEM",
            ));
        }
        Ok(())
    }
}

/// Go `strings.EqualFold`; ASCII folding is exact for "production" and
/// "development" (neither contains a letter with a non-ASCII fold).
fn is_production(app_env: &str) -> bool {
    app_env.eq_ignore_ascii_case("production")
}

fn default_sso_cookie_secure(app_env: &str, public_base_url: &str) -> bool {
    if app_env.eq_ignore_ascii_case("development") {
        return false;
    }
    url::Url::parse(public_base_url).is_ok_and(|url| url.scheme() == "https")
}

fn default_support_api_token(app_env: &str) -> &'static str {
    if app_env.eq_ignore_ascii_case("development") {
        "dev-support-token"
    } else {
        ""
    }
}

/// Go: `url.Parse` must succeed and yield a scheme and host.
///
/// The `url` crate is more lenient than Go in ways handled here: it strips
/// control characters and surrounding spaces, and accepts `https:host`.
fn validate_absolute_url(key: &'static str, raw: &str) -> Result<(), ConfigError> {
    let invalid = |reason: String| ConfigError::InvalidUrl {
        key,
        value: raw.to_owned(),
        reason,
    };
    if raw.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(invalid("net/url: invalid control character in URL".into()));
    }
    match url::Url::parse(raw) {
        Ok(url) => {
            // Go only sees a host after a literal `scheme://` at the start.
            let has_authority = raw.split_once(':').is_some_and(|(scheme, rest)| {
                scheme.eq_ignore_ascii_case(url.scheme()) && rest.starts_with("//")
            });
            if !has_authority || url.host_str().is_none_or(str::is_empty) {
                return Err(ConfigError::RelativeUrl(key));
            }
            Ok(())
        }
        Err(url::ParseError::RelativeUrlWithoutBase | url::ParseError::EmptyHost) => {
            Err(ConfigError::RelativeUrl(key))
        }
        Err(error) => Err(invalid(error.to_string())),
    }
}

fn validate_provider_group(prefix: &'static str, values: [&str; 3]) -> Result<(), ConfigError> {
    let filled = values
        .iter()
        .filter(|value| !value.trim().is_empty())
        .count();
    if filled == 0 || filled == values.len() {
        Ok(())
    } else {
        Err(ConfigError::IncompleteProvider(prefix))
    }
}

/// Env lookups with Go's helper semantics.
struct Env<F>(F);

impl<F: Fn(&str) -> Option<String>> Env<F> {
    /// Raw value; empty counts as unset.
    fn get(&self, key: &str) -> Option<String> {
        (self.0)(key).filter(|value| !value.is_empty())
    }

    /// Go `getEnv` (untrimmed).
    fn or(&self, key: &str, fallback: &str) -> String {
        self.get(key).unwrap_or_else(|| fallback.to_owned())
    }

    /// Go `strings.TrimSpace(getEnv(key, ""))`.
    fn trimmed(&self, key: &str) -> String {
        self.get(key)
            .map(|value| value.trim().to_owned())
            .unwrap_or_default()
    }

    /// Go `mustEnv`: whitespace-only values pass.
    fn required(&self, key: &'static str) -> Result<String, ConfigError> {
        self.get(key).ok_or(ConfigError::Missing(key))
    }

    /// Go `splitEnvList`: comma-separated, trimmed, empties dropped.
    fn list(&self, key: &str) -> Vec<String> {
        self.trimmed(key)
            .split(',')
            .map(str::trim)
            .filter(|part| !part.is_empty())
            .map(str::to_owned)
            .collect()
    }

    /// Go `durationEnv` (untrimmed).
    fn duration(&self, key: &'static str, fallback: Duration) -> Result<Duration, ConfigError> {
        match self.get(key) {
            None => Ok(fallback),
            Some(value) => {
                parse_duration(&value).map_err(|source| ConfigError::ParseDuration { key, source })
            }
        }
    }

    /// Go `intEnv` (trimmed).
    fn int(&self, key: &'static str, fallback: i64) -> Result<i64, ConfigError> {
        match self.trimmed(key).as_str() {
            "" => Ok(fallback),
            value => atoi(value).map_err(|source| ConfigError::ParseInt { key, source }),
        }
    }

    /// Go `boolEnv` (trimmed).
    fn boolean(&self, key: &'static str, fallback: bool) -> Result<bool, ConfigError> {
        match self.trimmed(key).as_str() {
            "" => Ok(fallback),
            value => parse_bool(value).map_err(|source| ConfigError::ParseBool { key, source }),
        }
    }
}

#[cfg(test)]
mod tests;
