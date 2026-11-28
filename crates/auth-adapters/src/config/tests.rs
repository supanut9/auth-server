use std::collections::HashMap;

use secrecy::{ExposeSecret, SecretString};
use time::Duration;

use super::{Config, ConfigError};

const PUBLIC_BASE_URL: &str = "https://auth.example";

/// The minimum env a development load needs.
fn base_env() -> HashMap<&'static str, String> {
    [
        ("PUBLIC_BASE_URL", PUBLIC_BASE_URL),
        ("AUTH_UI_BASE_URL", "https://ui.example"),
        ("DATABASE_URL", "postgres://localhost/auth_test"),
        ("JWT_ISSUER", PUBLIC_BASE_URL),
        ("JWT_PRIVATE_KEY_PEM", "test-private-key"),
        ("JWT_PUBLIC_KEY_PEM", "test-public-key"),
    ]
    .into_iter()
    .map(|(key, value)| (key, value.to_owned()))
    .collect()
}

fn load(env: &HashMap<&'static str, String>) -> Result<Config, ConfigError> {
    Config::from_env(|key| env.get(key).cloned())
}

fn load_with(overrides: &[(&'static str, &str)]) -> Result<Config, ConfigError> {
    let mut env = base_env();
    for (key, value) in overrides {
        env.insert(key, (*value).to_owned());
    }
    load(&env)
}

fn load_err(overrides: &[(&'static str, &str)]) -> String {
    load_with(overrides)
        .expect_err("expected an error")
        .to_string()
}

/// Go `baseTestConfig`.
fn base_test_config() -> Config {
    Config {
        app_name: String::new(),
        app_env: String::new(),
        http_addr: String::new(),
        public_base_url: "https://auth.example".into(),
        auth_ui_base_url: "https://ui.example".into(),
        post_logout_redirect_allowlist: Vec::new(),
        database_url: SecretString::default(),
        redis_url: SecretString::default(),
        jwt_issuer: "https://auth.example".into(),
        jwt_signing_alg: String::new(),
        jwt_private_key_path: String::new(),
        jwt_private_key_pem: "test-private-key".into(),
        jwt_public_key_path: String::new(),
        jwt_public_key_pem: "test-public-key".into(),
        sso_cookie_secure: true,
        sso_cookie_same_site: "lax".into(),
        sso_cookie_domain: String::new(),
        google_client_id: String::new(),
        google_client_secret: SecretString::default(),
        google_redirect_url: String::new(),
        github_client_id: String::new(),
        github_client_secret: SecretString::default(),
        github_redirect_url: String::new(),
        smtp_host: String::new(),
        smtp_port: String::new(),
        smtp_username: String::new(),
        smtp_password: SecretString::default(),
        smtp_from: String::new(),
        fixed_otp_code: String::new(),
        otp_test_hint_allowlist: Vec::new(),
        support_api_token: "dev-support-token".into(),
        cron_secret: None,
        platform_audience: String::new(),
        access_token_ttl: Duration::minutes(10),
        id_token_ttl: Duration::minutes(10),
        refresh_absolute_ttl: Duration::hours(24),
        refresh_inactive_ttl: Duration::hours(24),
        refresh_reuse_grace: Duration::ZERO,
        otp_challenge_ttl: Duration::minutes(10),
        otp_max_attempts: 6,
        otp_max_resends: 3,
        otp_resend_cooldown: Duration::minutes(1),
        authorization_request_ttl: Duration::minutes(10),
        authorization_code_ttl: Duration::minutes(5),
        sso_session_ttl: Duration::hours(24),
        flow_envelope_secret: SecretString::default(),
        flow_envelope_ttl: Duration::ZERO,
    }
}

// ---- Ports of internal/config/config_test.go ----

#[test]
fn load_flow_envelope_secret() {
    let mut env = base_env();
    env.insert("SUPPORT_API_TOKEN", "test-support-token".into());
    env.insert("FIXED_OTP_CODE", String::new());
    env.insert("OTP_TEST_HINT_ALLOWLIST", String::new());

    let valid_secret = "é".repeat(16);
    let dev_fallback = format!("dev-flow-envelope-secret-{PUBLIC_BASE_URL}-min-32-bytes");
    let cases: [(&str, &str, String, Option<&str>); 5] = [
        ("production missing", "production", String::new(), None),
        ("production blank", "production", " \t".into(), None),
        (
            "production short",
            "Production",
            format!(" {} ", "x".repeat(31)),
            None,
        ),
        (
            "production valid",
            "production",
            format!(" {valid_secret} "),
            Some(valid_secret.as_str()),
        ),
        (
            "development missing",
            "development",
            String::new(),
            Some(dev_fallback.as_str()),
        ),
    ];
    for (name, app_env, secret, want) in cases {
        let mut env = env.clone();
        env.insert("APP_ENV", app_env.into());
        env.insert("FLOW_ENVELOPE_SECRET", secret);
        match (load(&env), want) {
            (Err(error), None) => assert!(
                error.to_string().contains("FLOW_ENVELOPE_SECRET"),
                "{name}: unexpected error {error}"
            ),
            (Ok(cfg), Some(want)) => {
                assert_eq!(cfg.flow_envelope_secret.expose_secret(), want, "{name}");
            }
            (Ok(_), None) => panic!("{name}: expected FLOW_ENVELOPE_SECRET validation error"),
            (Err(error), Some(_)) => panic!("{name}: unexpected error {error}"),
        }
    }
}

#[test]
fn validate_rejects_invalid_sso_cookie_same_site() {
    let mut cfg = base_test_config();
    cfg.sso_cookie_same_site = "unsupported".into();
    let error = cfg.validate().expect_err("SameSite validation error");
    assert!(
        error.to_string().contains("SSO_COOKIE_SAME_SITE"),
        "{error}"
    );
}

#[test]
fn validate_rejects_same_site_none_without_secure() {
    let mut cfg = base_test_config();
    cfg.sso_cookie_same_site = "none".into();
    cfg.sso_cookie_secure = false;
    let error = cfg.validate().expect_err("secure cookie validation error");
    assert!(
        error
            .to_string()
            .contains("requires SSO_COOKIE_SECURE=true"),
        "{error}"
    );
}

#[test]
fn validate_rejects_invalid_otp_limits() {
    let mut cfg = base_test_config();
    cfg.otp_max_attempts = 0;
    let error = cfg.validate().expect_err("otp attempts validation error");
    assert!(error.to_string().contains("OTP_MAX_ATTEMPTS"), "{error}");
}

#[test]
fn validate_rejects_missing_support_token() {
    let mut cfg = base_test_config();
    cfg.support_api_token = SecretString::default();
    let error = cfg.validate().expect_err("support token validation error");
    assert!(error.to_string().contains("SUPPORT_API_TOKEN"), "{error}");
}

#[test]
fn base_test_config_is_valid() {
    base_test_config().validate().expect("valid");
}

// ---- Defaults and per-variable parsing ----

#[test]
fn defaults_for_every_env_var() {
    let cfg = load(&base_env()).expect("minimal env loads");

    let strings: [(&str, &str, &str); 23] = [
        ("APP_NAME", &cfg.app_name, "auth-server"),
        ("APP_ENV", &cfg.app_env, "development"),
        ("HTTP_ADDR", &cfg.http_addr, ":8050"),
        ("REDIS_URL", cfg.redis_url.expose_secret(), ""),
        ("JWT_SIGNING_ALG", &cfg.jwt_signing_alg, "RS256"),
        ("JWT_PRIVATE_KEY_PATH", &cfg.jwt_private_key_path, ""),
        ("JWT_PUBLIC_KEY_PATH", &cfg.jwt_public_key_path, ""),
        ("SSO_COOKIE_SAME_SITE", &cfg.sso_cookie_same_site, "lax"),
        ("SSO_COOKIE_DOMAIN", &cfg.sso_cookie_domain, ""),
        ("GOOGLE_CLIENT_ID", &cfg.google_client_id, ""),
        (
            "GOOGLE_CLIENT_SECRET",
            cfg.google_client_secret.expose_secret(),
            "",
        ),
        ("GOOGLE_REDIRECT_URL", &cfg.google_redirect_url, ""),
        ("GITHUB_CLIENT_ID", &cfg.github_client_id, ""),
        (
            "GITHUB_CLIENT_SECRET",
            cfg.github_client_secret.expose_secret(),
            "",
        ),
        ("GITHUB_REDIRECT_URL", &cfg.github_redirect_url, ""),
        ("SMTP_HOST", &cfg.smtp_host, ""),
        ("SMTP_PORT", &cfg.smtp_port, "587"),
        ("SMTP_USERNAME", &cfg.smtp_username, ""),
        ("SMTP_PASSWORD", cfg.smtp_password.expose_secret(), ""),
        ("SMTP_FROM", &cfg.smtp_from, ""),
        ("FIXED_OTP_CODE", &cfg.fixed_otp_code, ""),
        (
            "SUPPORT_API_TOKEN",
            cfg.support_api_token.expose_secret(),
            "dev-support-token",
        ),
        ("PLATFORM_AUDIENCE", &cfg.platform_audience, "platform-api"),
    ];
    for (key, got, want) in strings {
        assert_eq!(got, want, "{key}");
    }

    let durations = [
        (
            "ACCESS_TOKEN_TTL",
            cfg.access_token_ttl,
            Duration::minutes(10),
        ),
        ("ID_TOKEN_TTL", cfg.id_token_ttl, Duration::minutes(10)),
        (
            "REFRESH_TOKEN_ABSOLUTE_TTL",
            cfg.refresh_absolute_ttl,
            Duration::hours(720),
        ),
        (
            "REFRESH_TOKEN_INACTIVE_TTL",
            cfg.refresh_inactive_ttl,
            Duration::hours(168),
        ),
        (
            "REFRESH_TOKEN_REUSE_GRACE",
            cfg.refresh_reuse_grace,
            Duration::seconds(60),
        ),
        (
            "OTP_CHALLENGE_TTL",
            cfg.otp_challenge_ttl,
            Duration::minutes(10),
        ),
        (
            "OTP_RESEND_COOLDOWN",
            cfg.otp_resend_cooldown,
            Duration::minutes(1),
        ),
        (
            "AUTHORIZATION_REQUEST_TTL",
            cfg.authorization_request_ttl,
            Duration::minutes(10),
        ),
        (
            "AUTHORIZATION_CODE_TTL",
            cfg.authorization_code_ttl,
            Duration::minutes(5),
        ),
        ("SSO_SESSION_TTL", cfg.sso_session_ttl, Duration::hours(720)),
        (
            "FLOW_ENVELOPE_TTL",
            cfg.flow_envelope_ttl,
            Duration::minutes(10),
        ),
    ];
    for (key, got, want) in durations {
        assert_eq!(got, want, "{key}");
    }

    assert!(cfg.cron_secret.is_none(), "CRON_SECRET");
    assert_eq!(cfg.otp_max_attempts, 6, "OTP_MAX_ATTEMPTS");
    assert_eq!(cfg.otp_max_resends, 3, "OTP_MAX_RESENDS");
    assert!(
        cfg.post_logout_redirect_allowlist.is_empty(),
        "POST_LOGOUT_REDIRECT_ALLOWLIST"
    );
    assert!(
        cfg.otp_test_hint_allowlist.is_empty(),
        "OTP_TEST_HINT_ALLOWLIST"
    );
    // Development never defaults to Secure, even on https.
    assert!(!cfg.sso_cookie_secure, "SSO_COOKIE_SECURE");
    assert_eq!(
        cfg.flow_envelope_secret.expose_secret(),
        "dev-flow-envelope-secret-https://auth.example-min-32-bytes",
        "FLOW_ENVELOPE_SECRET"
    );

    // Required values are taken verbatim.
    assert_eq!(cfg.public_base_url, PUBLIC_BASE_URL);
    assert_eq!(cfg.auth_ui_base_url, "https://ui.example");
    assert_eq!(
        cfg.database_url.expose_secret(),
        "postgres://localhost/auth_test"
    );
    assert_eq!(cfg.jwt_issuer, PUBLIC_BASE_URL);
    assert_eq!(cfg.jwt_private_key_pem.expose_secret(), "test-private-key");
    assert_eq!(cfg.jwt_public_key_pem, "test-public-key");
}

#[test]
fn every_env_var_is_read() {
    type Check = fn(&Config) -> bool;
    let cases: &[(&'static str, &str, Check)] = &[
        ("CRON_SECRET", "test-cron-token", |c| {
            c.cron_secret.as_ref().map(ExposeSecret::expose_secret) == Some("test-cron-token")
        }),
        ("APP_NAME", "my-auth", |c| c.app_name == "my-auth"),
        ("APP_ENV", "Development", |c| c.app_env == "Development"),
        ("HTTP_ADDR", ":9000", |c| c.http_addr == ":9000"),
        ("PUBLIC_BASE_URL", "https://other.example", |c| {
            c.public_base_url == "https://other.example"
        }),
        ("AUTH_UI_BASE_URL", "https://ui2.example", |c| {
            c.auth_ui_base_url == "https://ui2.example"
        }),
        (
            "POST_LOGOUT_REDIRECT_ALLOWLIST",
            " https://a.example , ,https://b.example ",
            |c| c.post_logout_redirect_allowlist == ["https://a.example", "https://b.example"],
        ),
        ("DATABASE_URL", "postgres://db/x", |c| {
            c.database_url.expose_secret() == "postgres://db/x"
        }),
        ("REDIS_URL", " redis://cache ", |c| {
            c.redis_url.expose_secret() == "redis://cache"
        }),
        ("JWT_ISSUER", "https://issuer.example/", |c| {
            c.jwt_issuer == "https://issuer.example/"
        }),
        ("JWT_SIGNING_ALG", "RS512", |c| c.jwt_signing_alg == "RS512"),
        ("JWT_PRIVATE_KEY_PATH", " /keys/private.pem ", |c| {
            c.jwt_private_key_path == "/keys/private.pem"
        }),
        ("JWT_PRIVATE_KEY_PEM", " pem ", |c| {
            c.jwt_private_key_pem.expose_secret() == "pem"
        }),
        ("JWT_PUBLIC_KEY_PATH", " /keys/public.pem ", |c| {
            c.jwt_public_key_path == "/keys/public.pem"
        }),
        ("JWT_PUBLIC_KEY_PEM", " pub ", |c| {
            c.jwt_public_key_pem == "pub"
        }),
        ("SSO_COOKIE_SECURE", " true ", |c| c.sso_cookie_secure),
        ("SSO_COOKIE_SAME_SITE", " Strict ", |c| {
            c.sso_cookie_same_site == "strict"
        }),
        ("SSO_COOKIE_DOMAIN", " .example ", |c| {
            c.sso_cookie_domain == ".example"
        }),
        ("SMTP_USERNAME", "mailer", |c| c.smtp_username == "mailer"),
        ("SMTP_PASSWORD", " pw ", |c| {
            c.smtp_password.expose_secret() == " pw "
        }),
        ("SMTP_FROM", "no-reply@example.com", |c| {
            c.smtp_from == "no-reply@example.com"
        }),
        ("SMTP_PORT", "2525", |c| c.smtp_port == "2525"),
        ("FIXED_OTP_CODE", " 12345678 ", |c| {
            c.fixed_otp_code == "12345678"
        }),
        (
            "OTP_TEST_HINT_ALLOWLIST",
            "a@example.com,b@example.com",
            |c| c.otp_test_hint_allowlist == ["a@example.com", "b@example.com"],
        ),
        ("SUPPORT_API_TOKEN", "tok", |c| {
            c.support_api_token.expose_secret() == "tok"
        }),
        ("PLATFORM_AUDIENCE", "aud", |c| c.platform_audience == "aud"),
        ("ACCESS_TOKEN_TTL", "15m", |c| {
            c.access_token_ttl == Duration::minutes(15)
        }),
        ("ID_TOKEN_TTL", "1h30m", |c| {
            c.id_token_ttl == Duration::minutes(90)
        }),
        ("REFRESH_TOKEN_ABSOLUTE_TTL", "1440h", |c| {
            c.refresh_absolute_ttl == Duration::hours(1440)
        }),
        ("REFRESH_TOKEN_INACTIVE_TTL", "48h", |c| {
            c.refresh_inactive_ttl == Duration::hours(48)
        }),
        ("REFRESH_TOKEN_REUSE_GRACE", "500ms", |c| {
            c.refresh_reuse_grace == Duration::milliseconds(500)
        }),
        ("OTP_CHALLENGE_TTL", "5m", |c| {
            c.otp_challenge_ttl == Duration::minutes(5)
        }),
        ("OTP_MAX_ATTEMPTS", " 10 ", |c| c.otp_max_attempts == 10),
        ("OTP_MAX_RESENDS", "0", |c| c.otp_max_resends == 0),
        ("OTP_RESEND_COOLDOWN", "30s", |c| {
            c.otp_resend_cooldown == Duration::seconds(30)
        }),
        ("AUTHORIZATION_REQUEST_TTL", "2m", |c| {
            c.authorization_request_ttl == Duration::minutes(2)
        }),
        ("AUTHORIZATION_CODE_TTL", "60s", |c| {
            c.authorization_code_ttl == Duration::minutes(1)
        }),
        ("SSO_SESSION_TTL", "24h", |c| {
            c.sso_session_ttl == Duration::hours(24)
        }),
        ("FLOW_ENVELOPE_SECRET", " s3cret ", |c| {
            c.flow_envelope_secret.expose_secret() == "s3cret"
        }),
        ("FLOW_ENVELOPE_TTL", "3m", |c| {
            c.flow_envelope_ttl == Duration::minutes(3)
        }),
    ];
    for (key, value, check) in cases {
        let cfg = load_with(&[(key, value)]).unwrap_or_else(|e| panic!("{key}={value:?}: {e}"));
        assert!(check(&cfg), "{key}={value:?} not applied");
    }

    let smtp = load_with(&[
        ("SMTP_HOST", "smtp.example.com"),
        ("SMTP_FROM", "no-reply@example.com"),
    ])
    .expect("smtp config");
    assert_eq!(smtp.smtp_host, "smtp.example.com");

    for prefix in ["GOOGLE", "GITHUB"] {
        let env = base_env();
        let id = format!("{prefix}_CLIENT_ID");
        let secret = format!("{prefix}_CLIENT_SECRET");
        let redirect = format!("{prefix}_REDIRECT_URL");
        let cfg = Config::from_env(|key| match key {
            k if k == id => Some(" id ".into()),
            k if k == secret => Some(" secret ".into()),
            k if k == redirect => Some(" https://auth.example/cb ".into()),
            _ => env.get(key).cloned(),
        })
        .expect("provider config");
        let (got_id, got_secret, got_redirect) = if prefix == "GOOGLE" {
            (
                &cfg.google_client_id,
                &cfg.google_client_secret,
                &cfg.google_redirect_url,
            )
        } else {
            (
                &cfg.github_client_id,
                &cfg.github_client_secret,
                &cfg.github_redirect_url,
            )
        };
        assert_eq!(got_id, "id");
        assert_eq!(got_secret.expose_secret(), "secret");
        assert_eq!(got_redirect, "https://auth.example/cb");
    }
}

#[test]
fn empty_values_count_as_unset() {
    let cfg = load_with(&[
        ("APP_NAME", ""),
        ("ACCESS_TOKEN_TTL", ""),
        ("OTP_MAX_ATTEMPTS", "  "),
        ("SSO_COOKIE_SECURE", " "),
        ("SMTP_PORT", ""),
    ])
    .expect("loads");
    assert_eq!(cfg.app_name, "auth-server");
    assert_eq!(cfg.access_token_ttl, Duration::minutes(10));
    assert_eq!(cfg.otp_max_attempts, 6);
    assert_eq!(cfg.smtp_port, "587");

    assert_eq!(
        load_err(&[("PUBLIC_BASE_URL", "")]),
        "missing required env: PUBLIC_BASE_URL"
    );
}

#[test]
fn required_vars_in_go_order() {
    for key in [
        "PUBLIC_BASE_URL",
        "AUTH_UI_BASE_URL",
        "DATABASE_URL",
        "JWT_ISSUER",
    ] {
        let mut env = base_env();
        env.remove(key);
        let error = load(&env).expect_err(key).to_string();
        assert_eq!(error, format!("missing required env: {key}"));
    }
    assert_eq!(
        load(&HashMap::new()).expect_err("empty env").to_string(),
        "missing required env: PUBLIC_BASE_URL"
    );

    let mut env = base_env();
    env.remove("JWT_PRIVATE_KEY_PEM");
    assert_eq!(
        load(&env).expect_err("no private key").to_string(),
        "missing required env: JWT_PRIVATE_KEY_PATH or JWT_PRIVATE_KEY_PEM"
    );
    let mut env = base_env();
    env.insert("JWT_PUBLIC_KEY_PEM", "   ".into());
    assert_eq!(
        load(&env).expect_err("no public key").to_string(),
        "missing required env: JWT_PUBLIC_KEY_PATH or JWT_PUBLIC_KEY_PEM"
    );
    let mut env = base_env();
    env.remove("JWT_PRIVATE_KEY_PEM");
    env.insert("JWT_PRIVATE_KEY_PATH", "/keys/private.pem".into());
    load(&env).expect("path is enough");
}

#[test]
fn parse_errors_match_go() {
    let cases: &[(&'static str, &str, &str)] = &[
        (
            "ACCESS_TOKEN_TTL",
            "1d",
            r#"parse duration env ACCESS_TOKEN_TTL: time: unknown unit "d" in duration "1d""#,
        ),
        (
            "SSO_SESSION_TTL",
            "30",
            r#"parse duration env SSO_SESSION_TTL: time: missing unit in duration "30""#,
        ),
        (
            "FLOW_ENVELOPE_TTL",
            " 10m",
            r#"parse duration env FLOW_ENVELOPE_TTL: time: invalid duration " 10m""#,
        ),
        (
            "OTP_MAX_ATTEMPTS",
            "six",
            r#"parse int env OTP_MAX_ATTEMPTS: strconv.Atoi: parsing "six": invalid syntax"#,
        ),
        (
            "SSO_COOKIE_SECURE",
            "yes",
            r#"parse bool env SSO_COOKIE_SECURE: strconv.ParseBool: parsing "yes": invalid syntax"#,
        ),
    ];
    for (key, value, want) in cases {
        assert_eq!(load_err(&[(key, value)]), *want, "{key}={value:?}");
    }
}

#[test]
fn negative_durations_are_accepted_like_go() {
    let cfg = load_with(&[
        ("ACCESS_TOKEN_TTL", "-10m"),
        ("REFRESH_TOKEN_REUSE_GRACE", "-1s"),
    ])
    .expect("Go accepts negative TTLs");
    assert_eq!(cfg.access_token_ttl, Duration::minutes(-10));
    assert_eq!(cfg.refresh_reuse_grace, Duration::seconds(-1));

    for value in ["0s", "-1m"] {
        assert_eq!(
            load_err(&[("OTP_RESEND_COOLDOWN", value)]),
            "invalid OTP_RESEND_COOLDOWN: must be greater than zero"
        );
    }
}

#[test]
fn otp_limits() {
    assert_eq!(
        load_err(&[("OTP_MAX_ATTEMPTS", "-1")]),
        "invalid OTP_MAX_ATTEMPTS: must be greater than zero"
    );
    assert_eq!(
        load_err(&[("OTP_MAX_RESENDS", "-1")]),
        "invalid OTP_MAX_RESENDS: must be zero or greater"
    );
}

#[test]
fn absolute_url_rules() {
    for value in [
        "https://auth.example",
        "http://localhost:8050",
        "custom://host/path",
    ] {
        load_with(&[("AUTH_UI_BASE_URL", value)]).unwrap_or_else(|e| panic!("{value}: {e}"));
    }
    for value in [
        "/relative",
        "auth.example",
        "localhost:8050",
        "https://",
        "https:auth.example",
        "mailto:a@example.com",
        " https://auth.example",
    ] {
        assert_eq!(
            load_err(&[("AUTH_UI_BASE_URL", value)]),
            "invalid AUTH_UI_BASE_URL: must be an absolute URL",
            "{value:?}"
        );
    }
    assert!(
        load_err(&[("JWT_ISSUER", "https://auth.example:port")])
            .starts_with(r#"invalid JWT_ISSUER: parse "https://auth.example:port": "#)
    );
    assert!(
        load_err(&[("PUBLIC_BASE_URL", "https://auth.example/\u{7f}")])
            .ends_with("net/url: invalid control character in URL")
    );
    assert_eq!(
        load_err(&[("POST_LOGOUT_REDIRECT_ALLOWLIST", "https://a.example,/b")]),
        "invalid POST_LOGOUT_REDIRECT_ALLOWLIST: must be an absolute URL"
    );
}

#[test]
fn sso_cookie_secure_default() {
    let secure = |app_env: &str, base: &str| {
        load_with(&[
            ("APP_ENV", app_env),
            ("PUBLIC_BASE_URL", base),
            ("SUPPORT_API_TOKEN", "tok"),
            ("FLOW_ENVELOPE_SECRET", &"x".repeat(32)),
        ])
        .expect("loads")
        .sso_cookie_secure
    };
    assert!(!secure("development", "https://auth.example"));
    assert!(!secure("DEVELOPMENT", "https://auth.example"));
    assert!(secure("production", "https://auth.example"));
    assert!(secure("staging", "HTTPS://auth.example"));
    assert!(!secure("staging", "http://auth.example"));

    let explicit = load_with(&[
        ("APP_ENV", "staging"),
        ("SUPPORT_API_TOKEN", "tok"),
        ("SSO_COOKIE_SECURE", "false"),
    ])
    .expect("explicit value wins");
    assert!(!explicit.sso_cookie_secure);

    assert_eq!(
        load_err(&[("SSO_COOKIE_SAME_SITE", "none")]),
        "invalid cookie policy: SSO_COOKIE_SAME_SITE=none requires SSO_COOKIE_SECURE=true"
    );
    load_with(&[("SSO_COOKIE_SAME_SITE", "None"), ("SSO_COOKIE_SECURE", "1")])
        .expect("none + secure is valid");
    assert_eq!(
        load_err(&[("SSO_COOKIE_SAME_SITE", "relaxed")]),
        "invalid SSO_COOKIE_SAME_SITE: must be lax, strict, or none"
    );
}

#[test]
fn support_token_default_only_in_development() {
    let cfg = load_with(&[("APP_ENV", "Development")]).expect("dev default");
    assert_eq!(cfg.support_api_token.expose_secret(), "dev-support-token");
    assert_eq!(
        load_err(&[("APP_ENV", "test")]),
        "missing required env: SUPPORT_API_TOKEN"
    );
    assert_eq!(
        load_err(&[("SUPPORT_API_TOKEN", "   ")]),
        "missing required env: SUPPORT_API_TOKEN"
    );
}

#[test]
fn provider_groups_are_all_or_none() {
    for prefix in ["GOOGLE", "GITHUB"] {
        let present = [
            format!("{prefix}_CLIENT_ID"),
            format!("{prefix}_CLIENT_SECRET"),
            format!("{prefix}_REDIRECT_URL"),
        ];
        for missing in 0..present.len() {
            let env = base_env();
            let error = Config::from_env(|key| {
                if present
                    .iter()
                    .enumerate()
                    .any(|(i, k)| i != missing && k == key)
                {
                    Some("value".into())
                } else if key == present[missing] {
                    Some("   ".into())
                } else {
                    env.get(key).cloned()
                }
            })
            .expect_err("partial provider config")
            .to_string();
            assert_eq!(
                error,
                format!(
                    "incomplete {prefix} provider config: set client id, secret, and redirect url together"
                )
            );
        }
    }
}

#[test]
fn smtp_rules() {
    assert_eq!(
        load_err(&[("SMTP_HOST", "smtp.example.com")]),
        "missing required env: SMTP_FROM when SMTP_HOST is set"
    );
    assert_eq!(
        load_err(&[
            ("SMTP_HOST", "smtp.example.com"),
            ("SMTP_FROM", "a@example.com"),
            ("SMTP_PORT", "smtp"),
        ]),
        r#"invalid SMTP_PORT: strconv.Atoi: parsing "smtp": invalid syntax"#
    );
    load_with(&[
        ("SMTP_HOST", "smtp.example.com"),
        ("SMTP_FROM", "a@example.com"),
        ("SMTP_PORT", " 465 "),
    ])
    .expect("trimmed port is valid");
    // Without a host neither SMTP_FROM nor SMTP_PORT is checked.
    load_with(&[("SMTP_HOST", "   "), ("SMTP_PORT", "smtp")]).expect("smtp disabled");
}

#[test]
fn production_only_rules() {
    let prod: &[(&'static str, &str)] = &[
        ("APP_ENV", "PRODUCTION"),
        ("SUPPORT_API_TOKEN", "tok"),
        ("FLOW_ENVELOPE_SECRET", "0123456789abcdef0123456789abcdef"),
    ];
    let cfg = load_with(prod).expect("production loads");
    assert!(cfg.is_production());

    let with = |extra: (&'static str, &'static str)| {
        let mut overrides = prod.to_vec();
        overrides.push(extra);
        load_err(&overrides)
    };
    assert_eq!(
        with(("FIXED_OTP_CODE", "12345678")),
        "FIXED_OTP_CODE must not be set in production"
    );
    assert_eq!(
        with(("OTP_TEST_HINT_ALLOWLIST", "a@example.com")),
        "OTP_TEST_HINT_ALLOWLIST must not be set in production"
    );
    // A blank list or code is unset.
    let mut overrides = prod.to_vec();
    overrides.extend([("OTP_TEST_HINT_ALLOWLIST", " , "), ("FIXED_OTP_CODE", "  ")]);
    load_with(&overrides).expect("blank values are unset");

    // Outside production both are allowed.
    load_with(&[
        ("FIXED_OTP_CODE", "12345678"),
        ("OTP_TEST_HINT_ALLOWLIST", "a@example.com"),
    ])
    .expect("development allows test helpers");
}

#[test]
fn debug_redacts_secrets() {
    let cfg = load_with(&[
        ("SUPPORT_API_TOKEN", "super-secret-token"),
        ("CRON_SECRET", "secret-cron-token"),
    ])
    .expect("loads");
    let debug = format!("{cfg:?}");
    assert!(!debug.contains("super-secret-token"));
    assert!(!debug.contains("secret-cron-token"));
    assert!(!debug.contains("postgres://localhost/auth_test"));
    assert!(!debug.contains("dev-flow-envelope-secret"));
}
