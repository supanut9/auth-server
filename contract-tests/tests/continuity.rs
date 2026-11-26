//! Cutover continuity (AUTH-037): Go and Rust run at the same time against ONE
//! shared database with the same RSA key, envelope secret and support token.
//! Every artifact minted by one implementation must be accepted by the other:
//!
//! (a) SSO session cookie, (b) authorization code, (c) refresh rotation in
//! both directions, (d) refresh reuse detection across implementations,
//! (e) access/ID tokens at userinfo/introspect + identical JWKS,
//! (f) provider-state envelope and its burned JTI, (g) support sign-out.
//!
//! Gated: does nothing unless `CONTRACT_CONTINUITY=1`. Run it through
//! `contract-tests/run-continuity.sh`.

use std::fmt::Display;

use auth_contract_tests::dual::*;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde_json::Value;

struct Checks {
    results: Vec<(&'static str, String, bool, String)>,
}

impl Checks {
    fn check(&mut self, item: &'static str, what: impl Display, ok: bool, detail: impl Display) {
        let what = what.to_string();
        println!(
            "{} ({item}) {what}{}",
            if ok { "PASS" } else { "FAIL" },
            if ok {
                String::new()
            } else {
                format!(": {detail}")
            }
        );
        self.results.push((item, what, ok, detail.to_string()));
    }

    fn status(&mut self, item: &'static str, what: impl Display, reply: &Reply, expected: u16) {
        self.check(
            item,
            what,
            reply.status == expected,
            format!(
                "expected {expected}, got {} {}",
                reply.status,
                reply.text().chars().take(300).collect::<String>()
            ),
        );
    }

    fn error(
        &mut self,
        item: &'static str,
        what: impl Display,
        reply: &Reply,
        status: u16,
        error: &str,
        description: Option<&str>,
    ) {
        let body = reply.json();
        let ok = reply.status == status
            && body["error"] == error
            && description.is_none_or(|d| body["error_description"] == d);
        self.check(
            item,
            what,
            ok,
            format!(
                "expected {status} {error} {description:?}, got {} {}",
                reply.status,
                reply.text()
            ),
        );
    }
}

struct Pair {
    go: Target,
    rust: Target,
}

impl Pair {
    /// (minted-by, accepted-by) in both directions.
    fn directions(&self) -> [(&Target, &Target); 2] {
        [(&self.go, &self.rust), (&self.rust, &self.go)]
    }
}

struct Login {
    jar: Jar,
    sub: String,
}

/// OTP login on `t` (csrf → start → verify). Returns the browser jar.
async fn otp_login(t: &Target, fx: &Fixtures, email: &str, flow: &Flow) -> Login {
    let mut jar = Jar::default();
    jar.absorb(&Reply::send(t.get("/v1/auth/csrf")).await);
    let start = Reply::send(
        t.post("/v1/auth/otp/start")
            .json(&flow.body(&[("email", email)])),
    )
    .await;
    let challenge = start.field("otp_challenge_id");
    let verify = Reply::send(jar.apply(t.post("/v1/auth/otp/verify").json(&flow.body(&[
        ("email", email),
        ("otp_challenge_id", &challenge),
        ("code", &fx.otp_code),
    ]))))
    .await;
    assert_eq!(
        verify.status,
        200,
        "{} OTP login failed: {}",
        t.name,
        verify.text()
    );
    jar.absorb(&verify);
    let sub = verify.json()["account"]["id"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    Login { jar, sub }
}

async fn accept(t: &Target, jar: &Jar, flow: &Flow) -> Reply {
    let csrf = jar.csrf.clone().unwrap_or_default();
    Reply::send(
        jar.apply(
            t.post("/v1/auth/consent/accept")
                .json(&flow.body(&[("csrf_token", &csrf)])),
        ),
    )
    .await
}

fn token(reply: &Reply, key: &str) -> String {
    reply.json()[key].as_str().unwrap_or_default().to_owned()
}

async fn jwks(t: &Target) -> Reply {
    Reply::send(t.get("/.well-known/jwks.json")).await
}

/// Verify an RS256 JWT against a JWKS document (signature, iss, aud, exp).
fn verify_jwt(jwks: &Value, raw: &str, issuer: &str, audience: &str) -> Result<Value, String> {
    let header = decode_header(raw).map_err(|e| e.to_string())?;
    let kid = header.kid.ok_or("no kid")?;
    let key = jwks["keys"]
        .as_array()
        .and_then(|keys| keys.iter().find(|key| key["kid"] == kid.as_str()))
        .ok_or_else(|| format!("kid {kid} not in JWKS"))?;
    let decoding = DecodingKey::from_rsa_components(
        key["n"].as_str().unwrap_or_default(),
        key["e"].as_str().unwrap_or_default(),
    )
    .map_err(|e| e.to_string())?;
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[issuer]);
    validation.set_audience(&[audience]);
    decode::<Value>(raw, &decoding, &validation)
        .map(|data| data.claims)
        .map_err(|e| e.to_string())
}

#[tokio::test]
async fn go_and_rust_share_state_on_one_database() {
    if std::env::var("CONTRACT_CONTINUITY").as_deref() != Ok("1") {
        eprintln!("skipped: set CONTRACT_CONTINUITY=1 (see run-continuity.sh)");
        return;
    }
    let fx = Fixtures::from_env();
    let pair = Pair {
        go: Target::new(
            "go",
            &std::env::var("CONTRACT_GO_URL").expect("CONTRACT_GO_URL"),
        ),
        rust: Target::new(
            "rust",
            &std::env::var("CONTRACT_RUST_URL").expect("CONTRACT_RUST_URL"),
        ),
    };
    let mut checks = Checks {
        results: Vec::new(),
    };

    sessions_codes_and_tokens(&mut checks, &pair, &fx).await;
    refresh_rotation_and_reuse(&mut checks, &pair, &fx).await;
    envelopes(&mut checks, &pair, &fx).await;
    support_sign_out(&mut checks, &pair, &fx).await;

    let failed: Vec<_> = checks.results.iter().filter(|r| !r.2).collect();
    println!("\nContinuity summary by item:");
    for item in ["a", "b", "c", "d", "e", "f", "g"] {
        let total = checks.results.iter().filter(|r| r.0 == item).count();
        let bad = failed.iter().filter(|r| r.0 == item).count();
        println!("  ({item}) {}/{total} checks passed", total - bad);
    }
    assert!(
        failed.is_empty(),
        "{} continuity checks failed",
        failed.len()
    );
}

/// (a) SSO cookies, (b) authorization codes and (e) access/ID tokens and JWKS.
async fn sessions_codes_and_tokens(c: &mut Checks, pair: &Pair, fx: &Fixtures) {
    let go_jwks = jwks(&pair.go).await;
    let rust_jwks = jwks(&pair.rust).await;
    c.check(
        "e",
        "JWKS documents are byte-identical",
        go_jwks.status == 200 && go_jwks.body == rust_jwks.body,
        format!("go={} rust={}", go_jwks.text(), rust_jwks.text()),
    );
    let jwks_doc = go_jwks.json();

    for (minter, acceptor) in pair.directions() {
        let (m, a) = (minter.name, acceptor.name);
        let email = format!("continuity-{m}-session@example.test");
        let flow = Flow::new(&fx.browser, FULL_SCOPE, &format!("{m}-a"));
        let login = otp_login(minter, fx, &email, &flow).await;
        let sid = login.jar.sso.clone().unwrap_or_default();

        // (a) The session cookie minted by one side authenticates on the other.
        let me = Reply::send(login.jar.apply(acceptor.get("/v1/auth/me"))).await;
        c.check(
            "a",
            format!("{m} SSO cookie → {a} /v1/auth/me is the same account and session"),
            me.status == 200
                && me.json()["account_id"] == login.sub.as_str()
                && me.json()["session"]["id"] == sid.as_str(),
            me.text(),
        );

        // (a) Consent accepted on the other side with the minter's cookies
        // (stateless double-submit CSRF + shared session) issues a code.
        let accepted = accept(acceptor, &login.jar, &flow).await;
        let code = code_from(&accepted.field("redirect_to"));
        c.check(
            "a",
            format!("{m} session + CSRF cookies → {a} consent accept issues a code"),
            accepted.status == 200 && !code.is_empty(),
            accepted.text(),
        );

        // (b) That code (issued by the acceptor) is redeemed at the minter.
        let tokens = Reply::send(minter.exchange(&fx.browser, &flow, &code, &flow.verifier)).await;
        c.status(
            "b",
            format!("{a}-issued authorization code → {m} token endpoint (PKCE)"),
            &tokens,
            200,
        );

        // (a) prompt=none on the acceptor with the minter's cookie → code.
        let none = Flow::new(&fx.browser, FULL_SCOPE, &format!("{m}-a-none")).prompt("none");
        let reply = Reply::send(login.jar.apply(acceptor.authorize(&none.params))).await;
        let code = code_from(&reply.location());
        c.check(
            "a",
            format!("{m} SSO cookie → {a} authorize prompt=none issues a code"),
            reply.status == 302
                && !code.is_empty()
                && query_param(&reply.location(), "error").is_empty(),
            reply.location(),
        );

        // (b) Code minted by `minter` redeemed at `acceptor`: first a wrong
        // verifier on a separate code, then the real exchange.
        let wrong = Flow::new(&fx.browser, FULL_SCOPE, &format!("{m}-b-wrong")).prompt("none");
        let wrong_code = code_from(
            &Reply::send(login.jar.apply(minter.authorize(&wrong.params)))
                .await
                .location(),
        );
        let reply =
            Reply::send(acceptor.exchange(&fx.browser, &wrong, &wrong_code, "incorrect-verifier"))
                .await;
        c.error(
            "b",
            format!("{m}-issued code + wrong verifier → {a} rejects with pkce validation failed"),
            &reply,
            400,
            "invalid_grant",
            Some("pkce validation failed"),
        );
        let flow_b = Flow::new(&fx.browser, FULL_SCOPE, &format!("{m}-b")).prompt("none");
        let code = code_from(
            &Reply::send(login.jar.apply(minter.authorize(&flow_b.params)))
                .await
                .location(),
        );
        let tokens =
            Reply::send(acceptor.exchange(&fx.browser, &flow_b, &code, &flow_b.verifier)).await;
        c.status(
            "b",
            format!("{m}-issued authorization code → {a} token endpoint (PKCE)"),
            &tokens,
            200,
        );
        let replay =
            Reply::send(minter.exchange(&fx.browser, &flow_b, &code, &flow_b.verifier)).await;
        c.error(
            "b",
            format!("code redeemed at {a} is consumed for {m} too"),
            &replay,
            400,
            "invalid_grant",
            None,
        );

        // (e) Tokens: both sides verify the acceptor-minted JWTs; the
        // userinfo/introspect answers are identical on both servers.
        let access = token(&tokens, "access_token");
        let id_token = token(&tokens, "id_token");
        let claims = verify_jwt(&jwks_doc, &access, &fx.issuer, &fx.audience);
        c.check(
            "e",
            format!("{a}-issued access token verifies against the shared JWKS (sub, sid)"),
            claims.as_ref().is_ok_and(|claims| {
                claims["sub"] == login.sub.as_str() && claims["sid"] == sid.as_str()
            }),
            format!("{claims:?}"),
        );
        let id_claims = verify_jwt(&jwks_doc, &id_token, &fx.issuer, &fx.browser.id);
        c.check(
            "e",
            format!("{a}-issued ID token verifies against the shared JWKS"),
            id_claims
                .as_ref()
                .is_ok_and(|claims| claims["sub"] == login.sub.as_str()),
            format!("{id_claims:?}"),
        );
        for (name, raw, hint) in [
            ("access token", &access, "access_token"),
            ("ID token", &id_token, "access_token"),
        ] {
            let at_minter = Reply::send(minter.get(USERINFO).bearer_auth(raw)).await;
            let at_acceptor = Reply::send(acceptor.get(USERINFO).bearer_auth(raw)).await;
            c.check(
                "e",
                format!("{a}-issued {name} → {m} userinfo equals {a} userinfo"),
                at_minter.status == 200 && at_minter.json() == at_acceptor.json(),
                format!("{m}: {} | {a}: {}", at_minter.text(), at_acceptor.text()),
            );
            let at_minter = Reply::send(minter.introspect(&fx.worker, raw, hint)).await;
            let at_acceptor = Reply::send(acceptor.introspect(&fx.worker, raw, hint)).await;
            c.check(
                "e",
                format!("{a}-issued {name} → {m} introspect equals {a} introspect (active)"),
                at_minter.status == 200
                    && at_minter.json()["active"] == true
                    && at_minter.json() == at_acceptor.json(),
                format!("{m}: {} | {a}: {}", at_minter.text(), at_acceptor.text()),
            );
        }
    }

    // client_credentials tokens too.
    for (minter, acceptor) in pair.directions() {
        let reply = Reply::send(minter.form(
            TOKEN,
            &fx.worker,
            true,
            &[
                ("grant_type", "client_credentials"),
                ("scope", "trading.read"),
            ],
        ))
        .await;
        let access = token(&reply, "access_token");
        let at_minter = Reply::send(minter.introspect(&fx.worker, &access, "access_token")).await;
        let at_acceptor =
            Reply::send(acceptor.introspect(&fx.worker, &access, "access_token")).await;
        c.check(
            "e",
            format!(
                "{}-issued client_credentials token → {} introspect equals {} introspect",
                minter.name, acceptor.name, minter.name
            ),
            reply.status == 200
                && at_acceptor.json()["active"] == true
                && at_minter.json() == at_acceptor.json(),
            format!("{} | {}", at_minter.text(), at_acceptor.text()),
        );
    }
}

/// (c) refresh rotation across implementations and (d) reuse detection.
async fn refresh_rotation_and_reuse(c: &mut Checks, pair: &Pair, fx: &Fixtures) {
    for (minter, other) in pair.directions() {
        let (m, o) = (minter.name, other.name);
        let flow = Flow::new(&fx.browser, FULL_SCOPE, &format!("{m}-c"));
        let login = otp_login(
            minter,
            fx,
            &format!("continuity-{m}-refresh@example.test"),
            &flow,
        )
        .await;
        let code = code_from(&accept(minter, &login.jar, &flow).await.field("redirect_to"));
        let tokens = Reply::send(minter.exchange(&fx.browser, &flow, &code, &flow.verifier)).await;
        let first = token(&tokens, "refresh_token");

        // (c) minter → other rotates → minter rotates the other's token.
        let rotated = Reply::send(other.refresh(&fx.browser, &first)).await;
        let second = token(&rotated, "refresh_token");
        c.check(
            "c",
            format!("{m}-issued refresh token rotated by {o}"),
            rotated.status == 200 && !second.is_empty() && second != first,
            rotated.text(),
        );
        let rotated = Reply::send(minter.refresh(&fx.browser, &second)).await;
        let third = token(&rotated, "refresh_token");
        c.check(
            "c",
            format!("{o}-issued refresh token rotated back by {m}"),
            rotated.status == 200 && !third.is_empty() && third != second,
            rotated.text(),
        );
        for (who, t) in [(m, minter), (o, other)] {
            let active = Reply::send(t.introspect(&fx.worker, &third, "refresh_token")).await;
            let inactive = Reply::send(t.introspect(&fx.worker, &second, "refresh_token")).await;
            c.check(
                "c",
                format!("{who} sees the latest refresh active and the rotated one inactive"),
                active.json()["active"] == true
                    && inactive.json() == serde_json::json!({"active": false}),
                format!("{} | {}", active.text(), inactive.text()),
            );
        }

        // (d) Reuse of the token `minter` rotated (second) is detected by
        // `other`, and the whole chain dies on both sides.
        let reuse = Reply::send(other.refresh(&fx.browser, &second)).await;
        c.error(
            "d",
            format!("reuse of a {m}-rotated refresh token is rejected by {o}"),
            &reuse,
            400,
            "invalid_grant",
            None,
        );
        for (who, t) in [(m, minter), (o, other)] {
            let latest = Reply::send(t.introspect(&fx.worker, &third, "refresh_token")).await;
            c.check(
                "d",
                format!(
                    "after reuse detected by {o}, {who} reports the chain's latest token inactive"
                ),
                latest.json() == serde_json::json!({"active": false}),
                latest.text(),
            );
        }
        let refresh = Reply::send(minter.refresh(&fx.browser, &third)).await;
        c.error(
            "d",
            format!("{m} refuses the latest token of the chain {o} revoked"),
            &refresh,
            400,
            "invalid_grant",
            None,
        );
    }
}

/// (f) provider-state envelopes signed by one side verify on the other, and
/// the JTI burned in the shared table blocks a replay on the signer.
async fn envelopes(c: &mut Checks, pair: &Pair, fx: &Fixtures) {
    const CALLBACK: &str = "/v1/auth/login/callback/google";
    for (signer, verifier) in pair.directions() {
        let (s, v) = (signer.name, verifier.name);
        let flow = Flow::new(&fx.browser, FULL_SCOPE, &format!("{s}-f")).prompt("login");
        let start = Reply::send(signer.post("/v1/auth/login/google").json(&flow.body(&[]))).await;
        let state = query_param(&start.field("authorization_url"), "state");
        c.check(
            "f",
            format!("{s} POST /v1/auth/login/google returns a signed state"),
            start.status == 200 && state.contains('.'),
            start.text(),
        );

        // Negative control: a tampered envelope fails verification.
        let mut tampered = state.clone();
        let last = tampered.pop().unwrap_or('A');
        tampered.push(if last == 'A' { 'B' } else { 'A' });
        let reply = Reply::send(
            verifier.get_query(CALLBACK, [("state", tampered.as_str()), ("code", "bogus")]),
        )
        .await;
        c.error(
            "f",
            format!("control: tampered {s} envelope is rejected by {v} as invalid_state"),
            &reply,
            400,
            "invalid_state",
            Some("envelope: signature mismatch"),
        );

        let reply = Reply::send(
            verifier.get_query(CALLBACK, [("state", state.as_str()), ("code", "bogus")]),
        )
        .await;
        c.error(
            "f",
            format!(
                "{s}-signed envelope passes {v} verification (fails later at the provider exchange)"
            ),
            &reply,
            502,
            "provider_error",
            None,
        );
        let replay =
            Reply::send(signer.get_query(CALLBACK, [("state", state.as_str()), ("code", "bogus")]))
                .await;
        c.error(
            "f",
            format!("replaying that state at {s} fails: JTI burned by {v} in the shared DB"),
            &replay,
            400,
            "invalid_state",
            Some("oauth: jti replay"),
        );
    }
}

/// (g) support sign-out on one side revokes what the other side sees.
async fn support_sign_out(c: &mut Checks, pair: &Pair, fx: &Fixtures) {
    for (minter, operator) in pair.directions() {
        let (m, op) = (minter.name, operator.name);
        let flow = Flow::new(&fx.browser, FULL_SCOPE, &format!("{m}-g"));
        let login = otp_login(
            minter,
            fx,
            &format!("continuity-{m}-support@example.test"),
            &flow,
        )
        .await;
        let code = code_from(&accept(minter, &login.jar, &flow).await.field("redirect_to"));
        let tokens = Reply::send(minter.exchange(&fx.browser, &flow, &code, &flow.verifier)).await;
        let refresh = token(&tokens, "refresh_token");
        let sid = login.jar.sso.clone().unwrap_or_default();
        let path = format!("/v1/support/accounts/{}", login.sub);

        let summary_minter = Reply::send(minter.get(&path).bearer_auth(&fx.support_token)).await;
        let summary_operator =
            Reply::send(operator.get(&path).bearer_auth(&fx.support_token)).await;
        c.check(
            "g",
            format!("support summary of a {m} login is identical on {op}"),
            summary_minter.status == 200 && summary_minter.json() == summary_operator.json(),
            format!("{} | {}", summary_minter.text(), summary_operator.text()),
        );

        let signed_out = Reply::send(
            operator
                .post(&format!("{path}/sign-out"))
                .bearer_auth(&fx.support_token),
        )
        .await;
        let body = signed_out.json();
        c.check(
            "g",
            format!("{op} support sign-out revokes the {m}-created session and chain"),
            signed_out.status == 200
                && body["revoked_session_ids"] == serde_json::json!([sid])
                && body["revoked_refresh_chain_count"] == 1,
            signed_out.text(),
        );
        let me = Reply::send(login.jar.apply(minter.get("/v1/auth/me"))).await;
        c.error(
            "g",
            format!("{m} /v1/auth/me is unauthenticated after the {op} sign-out"),
            &me,
            401,
            "unauthenticated",
            None,
        );
        let refreshed = Reply::send(minter.refresh(&fx.browser, &refresh)).await;
        c.error(
            "g",
            format!("{m} refuses the refresh token revoked by {op}"),
            &refreshed,
            400,
            "invalid_grant",
            None,
        );
        let none = Flow::new(&fx.browser, FULL_SCOPE, &format!("{m}-g-none")).prompt("none");
        let reply = Reply::send(login.jar.apply(minter.authorize(&none.params))).await;
        c.check(
            "g",
            format!("{m} authorize prompt=none with the revoked session → login_required"),
            query_param(&reply.location(), "error") == "login_required",
            reply.location(),
        );
        let summary = Reply::send(minter.get(&path).bearer_auth(&fx.support_token))
            .await
            .json();
        c.check(
            "g",
            format!("{m} support summary shows the session and chain revoked"),
            summary["sessions"][0]["status"] == "revoked"
                && summary["refresh_token_chains"][0]["status"] == "revoked",
            summary,
        );
    }

    // Global logout on one side also ends the other side's view of the session.
    for (minter, other) in pair.directions() {
        let (m, o) = (minter.name, other.name);
        let flow = Flow::new(&fx.browser, FULL_SCOPE, &format!("{m}-g-logout"));
        let login = otp_login(
            minter,
            fx,
            &format!("continuity-{m}-logout@example.test"),
            &flow,
        )
        .await;
        let code = code_from(&accept(minter, &login.jar, &flow).await.field("redirect_to"));
        let tokens = Reply::send(minter.exchange(&fx.browser, &flow, &code, &flow.verifier)).await;
        let refresh = token(&tokens, "refresh_token");
        let logout = Reply::send(login.jar.apply(other.get("/v1/auth/logout/global"))).await;
        let me = Reply::send(login.jar.apply(minter.get("/v1/auth/me"))).await;
        let refreshed = Reply::send(minter.refresh(&fx.browser, &refresh)).await;
        c.check(
            "g",
            format!("{o} global logout of a {m} session: {m} /me 401 and refresh invalid_grant"),
            logout.status == 302 && me.status == 401 && refreshed.status == 400,
            format!("{} | {} | {}", logout.status, me.text(), refreshed.text()),
        );
    }
}
