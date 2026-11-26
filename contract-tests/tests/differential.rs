//! Differential run (AUTH-037): one scripted request sequence against the Go
//! server and the Rust server, each on its own freshly migrated and seeded
//! database with the same keys and secrets. Every response is normalized
//! (`normalize::Normalizer`) and compared; each difference must match an entry
//! in `ALLOWLIST`, which maps to the port plan's §3 accepted deviations.
//!
//! Gated: does nothing unless `CONTRACT_DIFFERENTIAL=1`. Run it through
//! `contract-tests/run-differential.sh`.

use auth_contract_tests::{
    differential::{Allowed, Recorder, report},
    dual::*,
};
use reqwest::{Method, header};
use serde_json::{Value, json};

/// Accepted Go-vs-Rust differences. Each entry names the plan §3 bullet it
/// implements; anything not matched here fails the run.
const ALLOWLIST: &[Allowed] = &[
    Allowed {
        id: "gin-bind-error-text",
        plan: "§3 accepted: gin validator error text for bind failures",
        why: "Go returns gin/encoding-json binding errors (`Key: '...' Error:Field validation ...`, \
              `invalid character ...`, `EOF`); Rust returns `<field> is required` or \
              `invalid JSON body`. Same status and `error` code; auth-ui only displays the text.",
        matches: |d, go, _| {
            d.path == ".body.error_description"
                && go["status"] == 400
                && go["body"]["error"] == "invalid_request"
                && is_go_bind_error(d.go_str())
                && (d.rust_str().ends_with(" is required") || d.rust_str() == "invalid JSON body")
        },
    },
    Allowed {
        id: "go-redirect-html-body",
        plan: "§3 accepted: the Go http.Redirect HTML body on 302s",
        why: "net/http writes `<a href=\"...\">Found</a>.` with `text/html; charset=utf-8` on \
              GET redirects (302 and gin's 301 trailing-slash redirect). The Rust port currently \
              mirrors it byte for byte (0 hits); the entry only lets a later Rust change to an \
              empty body with no Content-Type pass. Location and status must still match.",
        matches: |d, go, rust| {
            let redirect = |obs: &Value| {
                obs["status"]
                    .as_u64()
                    .is_some_and(|s| (300..400).contains(&s))
            };
            redirect(go)
                && redirect(rust)
                && match d.path.as_str() {
                    ".body" => d.go_str().starts_with("<a href=\"") && d.rust_str().is_empty(),
                    ".headers.content-type" => {
                        d.go_str() == "text/html; charset=utf-8" && d.rust.is_none()
                    }
                    _ => false,
                }
        },
    },
    Allowed {
        id: "provider-transport-error-text",
        plan: "§3 accepted (by extension): implementation error text that consumers only display",
        why: "provider_error's error_description is the HTTP client's transport error string \
              (Go net/http vs reqwest). The run routes provider calls to a closed local proxy so \
              both fail before reaching Google; status 502 and `error` match. NOT listed in the \
              plan verbatim: needs adding to docs/rust-port-deviations.md.",
        matches: |d, go, rust| {
            d.path == ".body.error_description"
                && go["status"] == 502
                && rust["status"] == 502
                && go["body"]["error"] == "provider_error"
                && rust["body"]["error"] == "provider_error"
        },
    },
];

fn is_go_bind_error(text: &str) -> bool {
    text.starts_with("Key: '")
        || text.starts_with("invalid character")
        || text == "EOF"
        || text == "unexpected EOF"
        || text.starts_with("json: ")
}

#[tokio::test]
async fn go_and_rust_responses_match() {
    if std::env::var("CONTRACT_DIFFERENTIAL").as_deref() != Ok("1") {
        eprintln!("skipped: set CONTRACT_DIFFERENTIAL=1 (see run-differential.sh)");
        return;
    }
    let fixtures = Fixtures::from_env();
    let go = Target::new(
        "go",
        &std::env::var("CONTRACT_GO_URL").expect("CONTRACT_GO_URL"),
    );
    let rust = Target::new(
        "rust",
        &std::env::var("CONTRACT_RUST_URL").expect("CONTRACT_RUST_URL"),
    );
    let mut go_run = Recorder::new("go");
    script(&mut go_run, &go, &fixtures).await;
    let mut rust_run = Recorder::new("rust");
    script(&mut rust_run, &rust, &fixtures).await;

    if let Ok(dir) = std::env::var("CONTRACT_DIFF_DUMP") {
        for run in [&go_run, &rust_run] {
            let steps: serde_json::Map<String, Value> = run.steps.iter().cloned().collect();
            let path = format!("{dir}/differential-{}.json", run.target);
            std::fs::write(&path, serde_json::to_string_pretty(&steps).unwrap())
                .expect("write differential dump");
        }
    }

    let (text, failures, _) = report(&go_run, &rust_run, ALLOWLIST);
    println!("{text}");
    assert_eq!(
        failures, 0,
        "{failures} Go/Rust differences are not in the allowlist"
    );
}

/// The scripted sequence. It must be deterministic: same emails, seeds and
/// order on both servers. It never asserts; it only records.
async fn script(rec: &mut Recorder, t: &Target, fx: &Fixtures) {
    health_and_metadata(rec, t).await;
    authorize_without_session(rec, t, fx).await;
    let alice = otp_login_and_tokens(rec, t, fx).await;
    confidential_client_and_reject(rec, t, fx, &alice).await;
    client_credentials(rec, t, fx).await;
    logout(rec, t, fx).await;
    support(rec, t, fx, &alice).await;
    provider(rec, t, fx).await;
    router_quirks(rec, t, fx).await;
}

async fn health_and_metadata(rec: &mut Recorder, t: &Target) {
    let long_id = "a".repeat(129);
    for path in ["/healthz", "/readyz"] {
        for (name, id) in [
            ("no request id", None),
            ("valid request id", Some("diff.request-01_OK")),
            ("invalid request id", Some("bad id")),
            ("overlong request id", Some(long_id.as_str())),
        ] {
            rec.step_with_request_id(&format!("GET {path} {name}"), t.get(path), id)
                .await;
        }
    }
    rec.step("discovery", t.get("/.well-known/openid-configuration"))
        .await;
    let jwks = rec.step("jwks", t.get("/.well-known/jwks.json")).await;
    // Same key on both servers: the JWKS documents must be byte-identical.
    rec.note("jwks raw bytes", json!(jwks.text()));
    for client in ["dev-browser", "contract-unknown", "knowledge-web"] {
        rec.step(
            &format!("public-info {client}"),
            t.get(&format!("/v1/clients/{client}/public-info")),
        )
        .await;
    }
    rec.step(
        "dev callback echo",
        t.get_query("/dev/callback", [("code", "abc"), ("state", "x y")]),
    )
    .await;
}

async fn authorize_without_session(rec: &mut Recorder, t: &Target, fx: &Fixtures) {
    let fatal: &[(&str, &[(&str, &str)])] = &[
        (
            "missing client_id",
            &[("client_id", ""), ("redirect_uri", "")],
        ),
        (
            "unknown client",
            &[("client_id", "contract-unknown"), ("redirect_uri", "")],
        ),
        (
            "inactive client",
            &[("client_id", &fx.inactive_client), ("redirect_uri", "")],
        ),
        ("missing redirect_uri", &[("redirect_uri", "")]),
        (
            "unregistered redirect_uri",
            &[("redirect_uri", "https://wrong.example.test/callback")],
        ),
        (
            "relative registered redirect_uri",
            &[
                ("client_id", &fx.malformed_client),
                ("redirect_uri", &fx.malformed_redirect),
            ],
        ),
    ];
    for (name, updates) in fatal {
        let mut flow = Flow::new(&fx.browser, FULL_SCOPE, "fatal");
        for (key, value) in *updates {
            flow = flow.with(key, value);
        }
        rec.step(
            &format!("authorize fatal: {name}"),
            t.authorize(&flow.params),
        )
        .await;
    }

    let too_long = "A".repeat(129);
    let bad_encoding = "*".repeat(43);
    let recoverable: &[(&str, &str)] = &[
        ("response_type", ""),
        ("response_type", "token"),
        ("state", ""),
        ("scope", ""),
        ("scope", "invalid.scope"),
        ("scope", "openid openid email"),
        ("nonce", ""),
        ("code_challenge", ""),
        ("code_challenge_method", "unknown"),
        ("code_challenge_method", "plain"),
        ("code_challenge_method", ""),
        ("code_challenge", "short"),
        ("code_challenge", &too_long),
        ("code_challenge", &bad_encoding),
        ("prompt", "consent"),
        ("prompt", "login none"),
    ];
    for (key, value) in recoverable {
        let flow = Flow::new(&fx.browser, FULL_SCOPE, "recoverable").with(key, value);
        rec.step(
            &format!("authorize {key}={value:.20}"),
            t.authorize(&flow.params),
        )
        .await;
    }

    let flow = Flow::new(&fx.browser, FULL_SCOPE, "nosession");
    rec.step("authorize no session", t.authorize(&flow.params))
        .await;
    let flow = Flow::new(&fx.browser, FULL_SCOPE, "nosession").prompt("none");
    rec.step(
        "authorize no session prompt=none",
        t.authorize(&flow.params),
    )
    .await;
    let flow = Flow::new(&fx.browser, FULL_SCOPE, "nosession")
        .prompt("login")
        .with("extra", "ignored");
    rec.step(
        "authorize no session prompt=login extra param",
        t.authorize(&flow.params),
    )
    .await;
    let flow = Flow::new(&fx.web, "openid", "confidential-no-pkce")
        .with("code_challenge", "")
        .with("code_challenge_method", "");
    rec.step(
        "authorize confidential client without PKCE",
        t.authorize(&flow.params),
    )
    .await;
}

struct Alice {
    sub: String,
    refresh: String,
    jar: Jar,
}

const OTP_START: &str = "/v1/auth/otp/start";
const OTP_VERIFY: &str = "/v1/auth/otp/verify";
const OTP_RESEND: &str = "/v1/auth/otp/resend";
const ACCEPT: &str = "/v1/auth/consent/accept";
const REJECT: &str = "/v1/auth/consent/reject";

/// OTP login + consent for one account. Records every step under `prefix`.
async fn login(
    rec: &mut Recorder,
    t: &Target,
    fx: &Fixtures,
    prefix: &str,
    email: &str,
    flow: &Flow,
) -> (Jar, Value) {
    let mut jar = Jar::default();
    let reply = rec
        .step(&format!("{prefix}: csrf"), t.get("/v1/auth/csrf"))
        .await;
    jar.absorb(&reply);
    let start = rec
        .step(
            &format!("{prefix}: otp start"),
            t.post(OTP_START).json(&flow.body(&[("email", email)])),
        )
        .await;
    let challenge = start.field("otp_challenge_id");
    let verify = rec
        .step(
            &format!("{prefix}: otp verify"),
            jar.apply(t.post(OTP_VERIFY).json(&flow.body(&[
                ("email", email),
                ("otp_challenge_id", &challenge),
                ("code", &fx.otp_code),
            ]))),
        )
        .await;
    jar.absorb(&verify);
    let csrf = jar.csrf.clone().unwrap_or_default();
    let accept = rec
        .step(
            &format!("{prefix}: consent accept"),
            jar.apply(t.post(ACCEPT).json(&flow.body(&[("csrf_token", &csrf)]))),
        )
        .await;
    let code = code_from(&accept.field("redirect_to"));
    let client = if flow.params["client_id"] == fx.web.id {
        &fx.web
    } else {
        &fx.browser
    };
    let tokens = rec
        .step(
            &format!("{prefix}: token exchange"),
            t.exchange(client, flow, &code, &flow.verifier),
        )
        .await;
    (jar, tokens.json())
}

async fn otp_login_and_tokens(rec: &mut Recorder, t: &Target, fx: &Fixtures) -> Alice {
    let email = "diff-alice@example.test";
    let flow = Flow::new(&fx.browser, "profile openid email", "alice");
    let mut jar = Jar::default();

    rec.step("me without cookie", t.get("/v1/auth/me")).await;
    rec.step(
        "me with unknown session cookie",
        t.get("/v1/auth/me")
            .header(header::COOKIE, "auth_sso_session=not-a-session"),
    )
    .await;
    let reply = rec.step("csrf", t.get("/v1/auth/csrf")).await;
    jar.absorb(&reply);

    // OTP start/verify/resend error branches.
    rec.step("otp start empty object", t.post(OTP_START).json(&json!({})))
        .await;
    rec.step(
        "otp start malformed JSON",
        t.post(OTP_START)
            .header(header::CONTENT_TYPE, "application/json")
            .body("{not json"),
    )
    .await;
    rec.step(
        "otp start invalid email",
        t.post(OTP_START)
            .json(&flow.body(&[("email", "not-an-email")])),
    )
    .await;
    let unknown = Flow::new(&fx.browser, FULL_SCOPE, "alice").with("client_id", "contract-unknown");
    rec.step(
        "otp start unknown client",
        t.post(OTP_START).json(&unknown.body(&[("email", email)])),
    )
    .await;
    let start = rec
        .step(
            "otp start",
            t.post(OTP_START).json(&flow.body(&[("email", email)])),
        )
        .await;
    let challenge = start.field("otp_challenge_id");
    rec.step(
        "otp resend within cooldown",
        t.post(OTP_RESEND)
            .json(&json!({"otp_challenge_id": challenge})),
    )
    .await;
    rec.step(
        "otp resend unknown challenge",
        t.post(OTP_RESEND)
            .json(&json!({"otp_challenge_id": "01900000-0000-7000-8000-000000000000"})),
    )
    .await;
    rec.step(
        "otp resend empty object",
        t.post(OTP_RESEND).json(&json!({})),
    )
    .await;
    rec.step(
        "otp verify missing challenge and code",
        t.post(OTP_VERIFY).json(&flow.body(&[("email", email)])),
    )
    .await;
    rec.step(
        "otp verify wrong code",
        t.post(OTP_VERIFY).json(&flow.body(&[
            ("email", email),
            ("otp_challenge_id", &challenge),
            ("code", "wrongOTP"),
        ])),
    )
    .await;
    rec.step(
        "otp verify wrong email",
        t.post(OTP_VERIFY).json(&flow.body(&[
            ("email", "diff-mallory@example.test"),
            ("otp_challenge_id", &challenge),
            ("code", &fx.otp_code),
        ])),
    )
    .await;
    rec.step("test-hint without email", t.get("/v1/auth/otp/test-hint"))
        .await;
    rec.step(
        "test-hint email not allowlisted",
        t.get_query("/v1/auth/otp/test-hint", [("email", email)]),
    )
    .await;
    rec.step(
        "test-hint allowlisted without challenge",
        t.get_query("/v1/auth/otp/test-hint", [("email", &fx.hint_email)]),
    )
    .await;
    rec.step(
        "otp start allowlisted hint email",
        t.post(OTP_START)
            .json(&flow.body(&[("email", &fx.hint_email)])),
    )
    .await;
    rec.step(
        "test-hint allowlisted",
        t.get_query("/v1/auth/otp/test-hint", [("email", &fx.hint_email)]),
    )
    .await;

    let verify_body = flow.body(&[
        ("email", email),
        ("otp_challenge_id", &challenge),
        ("code", &fx.otp_code),
    ]);
    let verify = rec
        .step(
            "otp verify",
            jar.apply(t.post(OTP_VERIFY).json(&verify_body)),
        )
        .await;
    jar.absorb(&verify);
    let sub = verify.json()["account"]["id"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    rec.step(
        "otp verify replay",
        jar.apply(t.post(OTP_VERIFY).json(&verify_body)),
    )
    .await;
    rec.step("me", jar.apply(t.get("/v1/auth/me"))).await;

    rec.step(
        "authorize with session needs consent",
        jar.apply(t.authorize(&flow.params)),
    )
    .await;
    let none = Flow::new(&fx.browser, FULL_SCOPE, "alice-none").prompt("none");
    rec.step(
        "authorize with session prompt=none consent_required",
        jar.apply(t.authorize(&none.params)),
    )
    .await;

    // Consent CSRF failures.
    let csrf = jar.csrf.clone().unwrap_or_default();
    let sso_only = Jar {
        sso: jar.sso.clone(),
        csrf: None,
    };
    let csrf_only = Jar {
        sso: None,
        csrf: jar.csrf.clone(),
    };
    rec.step(
        "consent accept missing csrf cookie",
        sso_only.apply(t.post(ACCEPT).json(&flow.body(&[("csrf_token", &csrf)]))),
    )
    .await;
    rec.step(
        "consent accept csrf mismatch",
        jar.apply(
            t.post(ACCEPT)
                .json(&flow.body(&[("csrf_token", "incorrect-csrf-token")])),
        ),
    )
    .await;
    rec.step(
        "consent accept missing csrf field",
        jar.apply(t.post(ACCEPT).json(&flow.body(&[]))),
    )
    .await;
    rec.step(
        "consent accept without session",
        csrf_only.apply(t.post(ACCEPT).json(&flow.body(&[("csrf_token", &csrf)]))),
    )
    .await;
    let bad_scope = Flow::new(&fx.browser, "invalid.scope", "alice");
    rec.step(
        "consent accept invalid scope",
        jar.apply(
            t.post(ACCEPT)
                .json(&bad_scope.body(&[("csrf_token", &csrf)])),
        ),
    )
    .await;
    let accept = rec
        .step(
            "consent accept",
            jar.apply(t.post(ACCEPT).json(&flow.body(&[("csrf_token", &csrf)]))),
        )
        .await;
    let code = code_from(&accept.field("redirect_to"));

    // Token endpoint errors that must not consume the code.
    rec.step(
        "token missing grant_type",
        t.form(TOKEN, &fx.browser, false, &[("code", &code)]),
    )
    .await;
    rec.step(
        "token unsupported grant_type",
        t.form(TOKEN, &fx.browser, false, &[("grant_type", "password")]),
    )
    .await;
    rec.step(
        "token without client",
        t.post(TOKEN)
            .form(&[("grant_type", "authorization_code"), ("code", &code)]),
    )
    .await;
    rec.step(
        "token unknown client",
        t.post(TOKEN).form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("client_id", "contract-unknown"),
        ]),
    )
    .await;
    rec.step(
        "token json body",
        t.post(TOKEN)
            .json(&json!({"grant_type": "authorization_code", "code": code})),
    )
    .await;
    rec.step(
        "token missing code",
        t.form(
            TOKEN,
            &fx.browser,
            false,
            &[("grant_type", "authorization_code")],
        ),
    )
    .await;
    rec.step(
        "token unknown code",
        t.exchange(&fx.browser, &flow, "unknown-code", &flow.verifier),
    )
    .await;

    let tokens = rec
        .step(
            "token exchange",
            t.exchange(&fx.browser, &flow, &code, &flow.verifier),
        )
        .await
        .json();
    rec.step(
        "token exchange replay",
        t.exchange(&fx.browser, &flow, &code, &flow.verifier),
    )
    .await;
    let access = tokens["access_token"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let id_token = tokens["id_token"].as_str().unwrap_or_default().to_owned();
    let refresh = tokens["refresh_token"]
        .as_str()
        .unwrap_or_default()
        .to_owned();

    rec.step(
        "userinfo access token",
        t.get(USERINFO).bearer_auth(&access),
    )
    .await;
    rec.step("userinfo id token", t.get(USERINFO).bearer_auth(&id_token))
        .await;
    rec.step("userinfo without token", t.get(USERINFO)).await;
    rec.step(
        "userinfo garbage token",
        t.get(USERINFO).bearer_auth("garbage"),
    )
    .await;
    rec.step(
        "userinfo basic scheme",
        t.get(USERINFO)
            .header(header::AUTHORIZATION, format!("Basic {access}")),
    )
    .await;
    rec.step(
        "introspect by public client",
        t.form(INTROSPECT, &fx.browser, false, &[("token", &access)]),
    )
    .await;
    rec.step(
        "introspect wrong worker secret",
        t.post(INTROSPECT)
            .basic_auth(&fx.worker.id, Some("wrong"))
            .form(&[("token", &access)]),
    )
    .await;
    for (name, token, hint) in [
        ("access", access.as_str(), "access_token"),
        ("id token", id_token.as_str(), "access_token"),
        ("refresh", refresh.as_str(), "refresh_token"),
        ("refresh without hint", refresh.as_str(), ""),
        ("unknown", "contract-unknown-token", ""),
        ("empty", "", ""),
    ] {
        rec.step(
            &format!("introspect {name}"),
            t.introspect(&fx.worker, token, hint),
        )
        .await;
    }

    let rotated = rec
        .step("refresh rotate", t.refresh(&fx.browser, &refresh))
        .await
        .json();
    let replacement = rotated["refresh_token"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    rec.step(
        "introspect rotated-out refresh",
        t.introspect(&fx.worker, &refresh, "refresh_token"),
    )
    .await;
    rec.step(
        "introspect replacement refresh",
        t.introspect(&fx.worker, &replacement, "refresh_token"),
    )
    .await;
    rec.step("refresh reuse", t.refresh(&fx.browser, &refresh))
        .await;
    rec.step(
        "introspect replacement after reuse",
        t.introspect(&fx.worker, &replacement, "refresh_token"),
    )
    .await;
    rec.step(
        "refresh replacement after reuse",
        t.refresh(&fx.browser, &replacement),
    )
    .await;
    rec.step(
        "refresh missing token",
        t.form(
            TOKEN,
            &fx.browser,
            false,
            &[("grant_type", "refresh_token")],
        ),
    )
    .await;

    // Remembered consent: direct code, PKCE failure consumes the code.
    let second = Flow::new(&fx.browser, FULL_SCOPE, "alice-2");
    let reply = rec
        .step(
            "authorize remembered consent",
            jar.apply(t.authorize(&second.params)),
        )
        .await;
    let code = code_from(&reply.location());
    rec.step(
        "token wrong verifier",
        t.exchange(&fx.browser, &second, &code, "incorrect-verifier"),
    )
    .await;
    rec.step(
        "token after wrong verifier",
        t.exchange(&fx.browser, &second, &code, &second.verifier),
    )
    .await;

    let third = Flow::new(&fx.browser, FULL_SCOPE, "alice-3");
    let reply = rec
        .step(
            "authorize remembered consent again",
            jar.apply(t.authorize(&third.params)),
        )
        .await;
    let code = code_from(&reply.location());
    let mut wrong_redirect = Flow::new(&fx.browser, FULL_SCOPE, "alice-3");
    wrong_redirect.params.insert(
        "redirect_uri".into(),
        "https://wrong.example.test/callback".into(),
    );
    rec.step(
        "token wrong redirect_uri",
        t.exchange(&fx.browser, &wrong_redirect, &code, &third.verifier),
    )
    .await;

    let fourth = Flow::new(&fx.browser, "openid", "alice-4").prompt("none");
    let reply = rec
        .step(
            "authorize prompt=none narrower scope",
            jar.apply(t.authorize(&fourth.params)),
        )
        .await;
    let code = code_from(&reply.location());
    let tokens = rec
        .step(
            "token exchange narrower scope",
            t.exchange(&fx.browser, &fourth, &code, &fourth.verifier),
        )
        .await
        .json();
    let narrow_access = tokens["access_token"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let narrow_refresh = tokens["refresh_token"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    rec.step(
        "userinfo openid-only token",
        t.get(USERINFO).bearer_auth(&narrow_access),
    )
    .await;
    rec.step(
        "refresh by another client",
        t.refresh(&fx.web, &narrow_refresh),
    )
    .await;
    for (name, token) in [
        ("empty", ""),
        ("unknown", "contract-unknown-token"),
        ("access token", narrow_access.as_str()),
        ("refresh", narrow_refresh.as_str()),
        ("refresh again", narrow_refresh.as_str()),
    ] {
        rec.step(
            &format!("revoke {name}"),
            t.form(REVOKE, &fx.browser, false, &[("token", token)]),
        )
        .await;
    }
    rec.step(
        "revoke without client",
        t.post(REVOKE).form(&[("token", "x")]),
    )
    .await;
    rec.step(
        "introspect revoked refresh",
        t.introspect(&fx.worker, &narrow_refresh, "refresh_token"),
    )
    .await;
    rec.step(
        "refresh revoked token",
        t.refresh(&fx.browser, &narrow_refresh),
    )
    .await;

    // A live chain for the support sign-out later.
    let fifth = Flow::new(&fx.browser, FULL_SCOPE, "alice-5");
    let reply = rec
        .step(
            "authorize for support chain",
            jar.apply(t.authorize(&fifth.params)),
        )
        .await;
    let code = code_from(&reply.location());
    let tokens = rec
        .step(
            "token exchange for support chain",
            t.exchange(&fx.browser, &fifth, &code, &fifth.verifier),
        )
        .await
        .json();
    Alice {
        sub,
        refresh: tokens["refresh_token"]
            .as_str()
            .unwrap_or_default()
            .to_owned(),
        jar,
    }
}

async fn confidential_client_and_reject(
    rec: &mut Recorder,
    t: &Target,
    fx: &Fixtures,
    alice: &Alice,
) {
    let jar = &alice.jar;
    let csrf = jar.csrf.clone().unwrap_or_default();
    let flow = Flow::new(&fx.web, FULL_SCOPE, "web");
    rec.step(
        "web authorize needs consent",
        jar.apply(t.authorize(&flow.params)),
    )
    .await;
    let accept = rec
        .step(
            "web consent accept",
            jar.apply(t.post(ACCEPT).json(&flow.body(&[("csrf_token", &csrf)]))),
        )
        .await;
    let code = code_from(&accept.field("redirect_to"));
    let fields = [
        ("grant_type", "authorization_code"),
        ("redirect_uri", flow.params["redirect_uri"].as_str()),
        ("code", code.as_str()),
        ("code_verifier", flow.verifier.as_str()),
    ];
    rec.step(
        "web token wrong secret",
        t.post(TOKEN)
            .basic_auth(&fx.web.id, Some("wrong-secret"))
            .form(&fields),
    )
    .await;
    rec.step(
        "web token secret missing",
        t.post(TOKEN)
            .form(&[fields.as_slice(), &[("client_id", fx.web.id.as_str())]].concat()),
    )
    .await;
    rec.step(
        "web token basic auth",
        t.form(TOKEN, &fx.web, true, &fields),
    )
    .await;

    let reject = Flow::new(&fx.web, "openid", "reject");
    rec.step(
        "consent reject missing csrf field",
        jar.apply(t.post(REJECT).json(&reject.body(&[]))),
    )
    .await;
    rec.step(
        "consent reject",
        jar.apply(t.post(REJECT).json(&reject.body(&[("csrf_token", &csrf)]))),
    )
    .await;
}

async fn client_credentials(rec: &mut Recorder, t: &Target, fx: &Fixtures) {
    for (name, basic, scope) in [
        (
            "basic duplicate scopes",
            true,
            "trading.write trading.read trading.read",
        ),
        ("post", false, "trading.read trading.write"),
        ("post empty scope", false, ""),
        ("openid scope", true, "openid"),
        ("mixed scope", true, "trading.read profile"),
        ("unknown scope", true, "unknown.scope"),
    ] {
        let reply = rec
            .step(
                &format!("client_credentials {name}"),
                t.form(
                    TOKEN,
                    &fx.worker,
                    basic,
                    &[("grant_type", "client_credentials"), ("scope", scope)],
                ),
            )
            .await;
        if name == "post" {
            let token = reply.field("access_token");
            rec.step(
                "userinfo client_credentials token",
                t.get(USERINFO).bearer_auth(&token),
            )
            .await;
            rec.step(
                "introspect client_credentials token",
                t.introspect(&fx.worker, &token, "access_token"),
            )
            .await;
        }
    }
    rec.step(
        "client_credentials public client",
        t.form(
            TOKEN,
            &fx.browser,
            false,
            &[
                ("grant_type", "client_credentials"),
                ("scope", "trading.read"),
            ],
        ),
    )
    .await;
    rec.step(
        "client_credentials wrong secret",
        t.post(TOKEN)
            .basic_auth(&fx.worker.id, Some("wrong-contract-secret"))
            .form(&[("grant_type", "client_credentials")]),
    )
    .await;
    rec.step(
        "client_credentials basic and post mixed",
        t.post(TOKEN)
            .basic_auth(&fx.worker.id, fx.worker.secret.as_deref())
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", "dev-browser"),
            ]),
    )
    .await;
}

async fn logout(rec: &mut Recorder, t: &Target, fx: &Fixtures) {
    // Bob: local logout and the Sprint 0 chain-ownership rule.
    let flow = Flow::new(&fx.browser, FULL_SCOPE, "bob");
    let (jar, tokens) = login(rec, t, fx, "bob", "diff-bob@example.test", &flow).await;
    let refresh = tokens["refresh_token"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let sub = rec_me_sub(rec, t, &jar, "bob: me").await;
    let summary = rec
        .step(
            "bob: support summary",
            t.get(&format!("/v1/support/accounts/{sub}"))
                .bearer_auth(&fx.support_token),
        )
        .await
        .json();
    let chain = summary["refresh_token_chains"][0]["id"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    rec.step(
        "logout local foreign chain without cookie",
        t.get_query("/v1/auth/logout", [("refresh_token_chain_id", &chain)]),
    )
    .await;
    let rotated = rec
        .step(
            "bob: refresh after foreign logout",
            t.refresh(&fx.browser, &refresh),
        )
        .await
        .json();
    let refresh = rotated["refresh_token"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    rec.step(
        "logout local own chain allowed redirect",
        jar.apply(t.get_query(
            "/v1/auth/logout",
            [
                ("refresh_token_chain_id", chain.as_str()),
                ("post_logout_redirect_uri", fx.logout_redirect.as_str()),
            ],
        )),
    )
    .await;
    rec.step(
        "bob: refresh after own local logout",
        t.refresh(&fx.browser, &refresh),
    )
    .await;
    rec.step(
        "bob: me after local logout",
        jar.apply(t.get("/v1/auth/me")),
    )
    .await;
    rec.step(
        "logout local unapproved redirect",
        t.get_query(
            "/v1/auth/logout",
            [(
                "post_logout_redirect_uri",
                "https://unapproved.example.test/x",
            )],
        ),
    )
    .await;

    // Carol: global logout.
    let flow = Flow::new(&fx.browser, FULL_SCOPE, "carol");
    let (jar, tokens) = login(rec, t, fx, "carol", "diff-carol@example.test", &flow).await;
    let refresh = tokens["refresh_token"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    rec.step(
        "logout global without cookie unapproved redirect",
        t.get_query(
            "/v1/auth/logout/global",
            [(
                "post_logout_redirect_uri",
                "https://unapproved.example.test/x",
            )],
        ),
    )
    .await;
    rec.step(
        "logout global",
        jar.apply(t.get_query(
            "/v1/auth/logout/global",
            [("post_logout_redirect_uri", &fx.logout_redirect)],
        )),
    )
    .await;
    rec.step(
        "carol: me after global logout",
        jar.apply(t.get("/v1/auth/me")),
    )
    .await;
    rec.step(
        "carol: refresh after global logout",
        t.refresh(&fx.browser, &refresh),
    )
    .await;
    rec.step(
        "carol: authorize after global logout",
        jar.apply(t.authorize(&flow.params)),
    )
    .await;
}

async fn rec_me_sub(rec: &mut Recorder, t: &Target, jar: &Jar, label: &str) -> String {
    let me = rec
        .step(label, jar.apply(t.get("/v1/auth/me")))
        .await
        .json();
    me["account_id"].as_str().unwrap_or_default().to_owned()
}

async fn support(rec: &mut Recorder, t: &Target, fx: &Fixtures, alice: &Alice) {
    let path = format!("/v1/support/accounts/{}", alice.sub);
    rec.step("support without token", t.get(&path)).await;
    rec.step(
        "support wrong token",
        t.get(&path).bearer_auth("invalid-contract-token"),
    )
    .await;
    rec.step(
        "support summary",
        t.get(&path).bearer_auth(&fx.support_token),
    )
    .await;
    rec.step(
        "support unknown account",
        t.get("/v1/support/accounts/01900000-0000-7000-8000-000000000000")
            .bearer_auth(&fx.support_token),
    )
    .await;
    rec.step(
        "support malformed account id",
        t.get("/v1/support/accounts/not-a-uuid")
            .bearer_auth(&fx.support_token),
    )
    .await;
    rec.step(
        "support sign-out",
        t.post(&format!("{path}/sign-out"))
            .bearer_auth(&fx.support_token),
    )
    .await;
    rec.step(
        "support summary after sign-out",
        t.get(&path).bearer_auth(&fx.support_token),
    )
    .await;
    rec.step(
        "support sign-out again",
        t.post(&format!("{path}/sign-out"))
            .bearer_auth(&fx.support_token),
    )
    .await;
    rec.step(
        "support sign-out unknown account",
        t.post("/v1/support/accounts/01900000-0000-7000-8000-000000000000/sign-out")
            .bearer_auth(&fx.support_token),
    )
    .await;
    rec.step(
        "alice: refresh after support sign-out",
        t.refresh(&fx.browser, &alice.refresh),
    )
    .await;
    rec.step(
        "alice: me after support sign-out",
        alice.jar.apply(t.get("/v1/auth/me")),
    )
    .await;
}

async fn provider(rec: &mut Recorder, t: &Target, fx: &Fixtures) {
    let flow = Flow::new(&fx.browser, FULL_SCOPE, "provider");
    rec.step(
        "github login start unconfigured",
        t.post("/v1/auth/login/github").json(&flow.body(&[])),
    )
    .await;
    rec.step(
        "google login start empty object",
        t.post("/v1/auth/login/google").json(&json!({})),
    )
    .await;
    let unknown =
        Flow::new(&fx.browser, FULL_SCOPE, "provider").with("client_id", "contract-unknown");
    rec.step(
        "google login start unknown client",
        t.post("/v1/auth/login/google").json(&unknown.body(&[])),
    )
    .await;
    let bad_scope = Flow::new(&fx.browser, "invalid.scope", "provider");
    rec.step(
        "google login start invalid scope",
        t.post("/v1/auth/login/google").json(&bad_scope.body(&[])),
    )
    .await;
    let mut states = Vec::new();
    for index in 1..=2 {
        let reply = rec
            .step(
                &format!("google login start #{index}"),
                t.post("/v1/auth/login/google")
                    .json(&flow.clone_prompt("login").body(&[])),
            )
            .await;
        states.push(query_param(&reply.field("authorization_url"), "state"));
    }
    let callback = "/v1/auth/login/callback/google";
    rec.step("google callback without params", t.get(callback))
        .await;
    rec.step(
        "google callback missing code",
        t.get_query(callback, [("state", &states[0])]),
    )
    .await;
    let mut tampered = states[0].clone();
    let last = tampered.pop().unwrap_or('A');
    tampered.push(if last == 'A' { 'B' } else { 'A' });
    rec.step(
        "google callback tampered state",
        t.get_query(callback, [("state", tampered.as_str()), ("code", "bogus")]),
    )
    .await;
    rec.step(
        "google callback malformed state",
        t.get_query(callback, [("state", "no-dot"), ("code", "bogus")]),
    )
    .await;
    rec.step(
        "github callback with google state",
        t.get_query(
            "/v1/auth/login/callback/github",
            [("state", states[0].as_str()), ("code", "bogus")],
        ),
    )
    .await;
    rec.step(
        "google callback bogus provider code",
        t.get_query(callback, [("state", states[1].as_str()), ("code", "bogus")]),
    )
    .await;
    rec.step(
        "google callback replayed state",
        t.get_query(callback, [("state", states[1].as_str()), ("code", "bogus")]),
    )
    .await;
}

trait ClonePrompt {
    fn clone_prompt(&self, prompt: &str) -> Flow;
}

impl ClonePrompt for Flow {
    fn clone_prompt(&self, prompt: &str) -> Flow {
        let mut params = self.params.clone();
        params.insert("prompt".into(), prompt.into());
        Flow {
            params,
            verifier: self.verifier.clone(),
        }
    }
}

async fn router_quirks(rec: &mut Recorder, t: &Target, fx: &Fixtures) {
    rec.step("unknown path", t.get("/contract-unknown-path"))
        .await;
    rec.step("POST health", t.post("/healthz")).await;
    rec.step("PUT token", t.request(Method::PUT, TOKEN)).await;
    rec.step("HEAD health", t.request(Method::HEAD, "/healthz"))
        .await;
    rec.step("GET health trailing slash", t.get("/healthz/"))
        .await;
    rec.step(
        "GET health trailing slash with query",
        t.get("/healthz/?probe=1"),
    )
    .await;
    rec.step("POST token trailing slash", t.post("/v1/oauth2/token/"))
        .await;
    rec.step("GET unknown trailing slash", t.get("/contract-unknown/"))
        .await;
    rec.step("GET double slash", t.get("//healthz")).await;
    rec.step("GET upper-case path", t.get("/HEALTHZ")).await;
    for (name, path, origin) in [
        (
            "OPTIONS unknown allowed origin",
            "/contract-unknown-path",
            Some(fx.ui.as_str()),
        ),
        ("OPTIONS token allowed origin", TOKEN, Some(fx.ui.as_str())),
        ("OPTIONS token no origin", TOKEN, None),
        (
            "OPTIONS token foreign origin",
            TOKEN,
            Some("https://evil.example.test"),
        ),
    ] {
        let mut request = t.request(Method::OPTIONS, path);
        if let Some(origin) = origin {
            request = request.header("Origin", origin);
        }
        rec.step(name, request).await;
    }
    rec.step(
        "GET health allowed origin",
        t.get("/healthz").header("Origin", &fx.ui),
    )
    .await;
    rec.step(
        "GET health foreign origin",
        t.get("/healthz")
            .header("Origin", "https://evil.example.test"),
    )
    .await;
}
