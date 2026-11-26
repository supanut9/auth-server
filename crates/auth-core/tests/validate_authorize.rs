//! Port of `internal/application/oauth/validate_test.go`, plus check-order,
//! PKCE and scope cases.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use auth_core::domain::{ClientId, ClientStatus, ClientType, OAuthClient};
use auth_core::oauth::{
    AuthorizeRequest, AuthorizeRequestValidator, ValidatedAuthorizeRequest, ValidationError,
    validate,
};
use auth_core::ports::{OAuthClientRepository, RepoError, RepoResult};

use ValidationError as E;

/// In-memory client registry. `fail_with_transport_error` makes every lookup
/// fail with a non-`NotFound` error.
#[derive(Default)]
struct FakeClients {
    clients: HashMap<String, OAuthClient>,
    fail_with_transport_error: bool,
}

impl FakeClients {
    fn with(clients: impl IntoIterator<Item = OAuthClient>) -> Self {
        Self {
            clients: clients
                .into_iter()
                .map(|c| (c.client_id.as_str().to_owned(), c))
                .collect(),
            fail_with_transport_error: false,
        }
    }
}

#[async_trait]
impl OAuthClientRepository for FakeClients {
    async fn create(&self, client: OAuthClient) -> RepoResult<OAuthClient> {
        Ok(client)
    }

    async fn find_by_client_id(&self, client_id: &ClientId) -> RepoResult<OAuthClient> {
        if self.fail_with_transport_error {
            return Err(RepoError::other("connection reset"));
        }
        self.clients
            .get(client_id.as_str())
            .cloned()
            .ok_or(RepoError::NotFound)
    }
}

fn valid_public_client() -> OAuthClient {
    OAuthClient {
        client_id: ClientId::new("trading-web"),
        client_type: ClientType::Public,
        status: ClientStatus::Active,
        redirect_uris: vec!["https://trading.example.com/cb".to_owned()],
        allowed_scopes: "openid email profile".to_owned(),
        ..OAuthClient::default()
    }
}

fn valid_confidential_client() -> OAuthClient {
    OAuthClient {
        client_id: ClientId::new("service"),
        client_type: ClientType::Confidential,
        ..valid_public_client()
    }
}

/// 64-char base64url (S256 typical): passes the length and encoding checks.
const VALID_CHALLENGE: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_AB";

fn valid_request() -> AuthorizeRequest {
    AuthorizeRequest {
        response_type: "code".to_owned(),
        client_id: "trading-web".to_owned(),
        redirect_uri: "https://trading.example.com/cb".to_owned(),
        scope: "openid email profile".to_owned(),
        state: "xyz".to_owned(),
        nonce: "n123".to_owned(),
        code_challenge: VALID_CHALLENGE.to_owned(),
        code_challenge_method: "S256".to_owned(),
        prompt: String::new(),
    }
}

fn confidential_request() -> AuthorizeRequest {
    AuthorizeRequest {
        client_id: "service".to_owned(),
        ..valid_request()
    }
}

fn repo() -> FakeClients {
    FakeClients::with([valid_public_client(), valid_confidential_client()])
}

async fn run(
    clients: &FakeClients,
    request: &AuthorizeRequest,
) -> Result<ValidatedAuthorizeRequest, ValidationError> {
    validate(clients, request).await
}

async fn expect_err(clients: &FakeClients, request: &AuthorizeRequest) -> ValidationError {
    match run(clients, request).await {
        Ok(v) => panic!("expected an error, got {v:?}"),
        Err(error) => error,
    }
}

async fn expect_ok(clients: &FakeClients, request: &AuthorizeRequest) -> ValidatedAuthorizeRequest {
    match run(clients, request).await {
        Ok(v) => v,
        Err(error) => panic!("unexpected error: {error}"),
    }
}

// ---------- port of validate_test.go ----------

#[tokio::test]
async fn happy_path() {
    let v = expect_ok(&repo(), &valid_request()).await;
    assert_eq!(v.client().client_id, "trading-web");
    assert_eq!(v.scopes().to_string(), "email openid profile");
    assert_eq!(v.request().scope, "email openid profile");
}

#[tokio::test]
async fn fatal_errors() {
    type Mutation = fn(&mut AuthorizeRequest);
    let cases: [(&str, Mutation, &str, ValidationError); 4] = [
        (
            "missing client_id",
            |r| r.client_id.clear(),
            "invalid_request",
            E::ClientIdRequired,
        ),
        (
            "unknown client_id",
            |r| r.client_id = "nope".to_owned(),
            "invalid_client",
            E::UnknownClient,
        ),
        (
            "missing redirect_uri",
            |r| r.redirect_uri.clear(),
            "invalid_request",
            E::RedirectUriRequired,
        ),
        (
            "mismatched redirect_uri",
            |r| r.redirect_uri = "https://evil.example.com/cb".to_owned(),
            "invalid_request",
            E::RedirectUriNotRegistered,
        ),
    ];
    let clients = repo();
    for (name, mutate, code, want) in cases {
        let mut request = valid_request();
        mutate(&mut request);
        let error = expect_err(&clients, &request).await;
        assert_eq!(error.code().as_str(), code, "{name}: {error}");
        assert_eq!(error, want, "{name}");
        assert!(error.is_fatal(), "{name}: expected fatal");
    }
}

#[tokio::test]
async fn recoverable_errors() {
    type Mutation = fn(&mut AuthorizeRequest);
    let cases: [(&str, Mutation, &str, ValidationError); 10] = [
        (
            "missing response_type",
            |r| r.response_type.clear(),
            "invalid_request",
            E::ResponseTypeRequired,
        ),
        (
            "unsupported response_type",
            |r| r.response_type = "token".to_owned(),
            "unsupported_response_type",
            E::UnsupportedResponseType,
        ),
        (
            "missing state",
            |r| r.state.clear(),
            "invalid_request",
            E::StateRequired,
        ),
        (
            "missing scope",
            |r| r.scope.clear(),
            "invalid_scope",
            E::ScopeRequired,
        ),
        (
            "unauthorized scope",
            |r| r.scope = "openid admin".to_owned(),
            "invalid_scope",
            E::ScopeNotAllowed,
        ),
        (
            "openid missing nonce",
            |r| r.nonce.clear(),
            "invalid_request",
            E::NonceRequired,
        ),
        (
            "public client missing pkce",
            |r| {
                r.code_challenge.clear();
                r.code_challenge_method.clear();
            },
            "invalid_request",
            E::CodeChallengeRequired,
        ),
        (
            "public client with plain pkce",
            |r| r.code_challenge_method = "plain".to_owned(),
            "invalid_request",
            E::PublicClientRequiresS256,
        ),
        (
            "unsupported pkce method",
            |r| r.code_challenge_method = "S128".to_owned(),
            "invalid_request",
            E::UnsupportedCodeChallengeMethod,
        ),
        (
            "pkce challenge too short",
            |r| r.code_challenge = "abc".to_owned(),
            "invalid_request",
            E::CodeChallengeLength,
        ),
    ];
    let clients = repo();
    for (name, mutate, code, want) in cases {
        let mut request = valid_request();
        mutate(&mut request);
        let error = expect_err(&clients, &request).await;
        assert_eq!(error.code().as_str(), code, "{name}: {error}");
        assert_eq!(error, want, "{name}");
        assert!(error.is_recoverable(), "{name}: expected recoverable");
    }
}

#[tokio::test]
async fn confidential_client_allows_plain_pkce() {
    let request = AuthorizeRequest {
        code_challenge_method: "plain".to_owned(),
        ..confidential_request()
    };
    let v = expect_ok(&repo(), &request).await;
    assert_eq!(v.request().code_challenge_method, "plain");
}

#[tokio::test]
async fn confidential_client_allows_missing_pkce() {
    let request = AuthorizeRequest {
        code_challenge: String::new(),
        code_challenge_method: String::new(),
        ..confidential_request()
    };
    let v = expect_ok(&repo(), &request).await;
    assert_eq!(v.request().code_challenge, "");
    assert_eq!(v.request().code_challenge_method, "");
}

#[tokio::test]
async fn canonicalizes_scope_and_method() {
    let request = AuthorizeRequest {
        scope: "profile  email   openid email".to_owned(),
        code_challenge: String::new(),
        code_challenge_method: String::new(),
        ..confidential_request()
    };
    let v = expect_ok(&repo(), &request).await;
    assert_eq!(v.request().scope, "email openid profile");
}

#[tokio::test]
async fn inactive_client_rejected() {
    let client = OAuthClient {
        status: ClientStatus::parse("disabled"),
        ..valid_public_client()
    };
    let error = expect_err(&FakeClients::with([client]), &valid_request()).await;
    assert_eq!(error, E::ClientNotActive);
    assert_eq!(error.code().as_str(), "invalid_client");
    assert_eq!(error.description(), "client is not active");
    assert!(error.is_fatal());
}

// ---------- client lookup and status ----------

#[tokio::test]
async fn unknown_client_description() {
    let request = AuthorizeRequest {
        client_id: "nope".to_owned(),
        ..valid_request()
    };
    let error = expect_err(&repo(), &request).await;
    assert_eq!(error.to_string(), "invalid_client: client_id is unknown");
}

#[tokio::test]
async fn repository_transport_error_reads_as_unknown_client() {
    let clients = FakeClients {
        fail_with_transport_error: true,
        ..repo()
    };
    assert_eq!(
        expect_err(&clients, &valid_request()).await,
        E::UnknownClient
    );
}

#[tokio::test]
async fn client_id_lookup_is_exact() {
    let request = AuthorizeRequest {
        client_id: "Trading-Web".to_owned(),
        ..valid_request()
    };
    assert_eq!(expect_err(&repo(), &request).await, E::UnknownClient);
}

#[tokio::test]
async fn empty_status_counts_as_active() {
    let client = OAuthClient {
        status: ClientStatus::default(),
        ..valid_public_client()
    };
    expect_ok(&FakeClients::with([client]), &valid_request()).await;
}

#[tokio::test]
async fn status_match_is_exact() {
    for status in ["Active", "ACTIVE", " active", "revoked", "disabled"] {
        let client = OAuthClient {
            status: ClientStatus::parse(status),
            ..valid_public_client()
        };
        let error = expect_err(&FakeClients::with([client]), &valid_request()).await;
        assert_eq!(error, E::ClientNotActive, "status {status:?}");
    }
}

// ---------- redirect_uri ----------

#[tokio::test]
async fn redirect_uri_match_is_exact_and_case_sensitive() {
    let mismatches = [
        "https://Trading.example.com/cb",
        "HTTPS://trading.example.com/cb",
        "https://trading.example.com/CB",
        "https://trading.example.com/cb/",
        "https://trading.example.com/cb?x=1",
        "https://trading.example.com/cb#f",
        "https://trading.example.com:443/cb",
        " https://trading.example.com/cb",
        "https://trading.example.com/c",
    ];
    for redirect_uri in mismatches {
        let request = AuthorizeRequest {
            redirect_uri: redirect_uri.to_owned(),
            ..valid_request()
        };
        let error = expect_err(&repo(), &request).await;
        assert_eq!(error, E::RedirectUriNotRegistered, "{redirect_uri:?}");
        assert_eq!(
            error.description(),
            "redirect_uri does not match a registered URI"
        );
    }
}

#[tokio::test]
async fn any_registered_redirect_uri_is_accepted() {
    let client = OAuthClient {
        redirect_uris: vec![
            "https://a.example.com/cb".to_owned(),
            "https://trading.example.com/cb?tab=1#top".to_owned(),
            "com.example.app://oauth".to_owned(),
        ],
        ..valid_public_client()
    };
    let clients = FakeClients::with([client]);
    for redirect_uri in [
        "https://a.example.com/cb",
        "https://trading.example.com/cb?tab=1#top",
        "com.example.app://oauth",
    ] {
        let request = AuthorizeRequest {
            redirect_uri: redirect_uri.to_owned(),
            ..valid_request()
        };
        let v = expect_ok(&clients, &request).await;
        assert_eq!(v.request().redirect_uri, redirect_uri);
    }
}

#[tokio::test]
async fn registered_but_not_absolute_redirect_uri_is_fatal() {
    let not_absolute = [
        "/cb",
        "//trading.example.com/cb",
        "trading.example.com/cb",
        "myapp:callback",
        "com.example.app:/callback",
        "https:///cb",
        "https://exa mple.com/cb",
        "https://example.com:80a/cb",
        "https://a:1:2/cb",
        "https://[127.0.0.1]/cb",
        "https://example.com/c%zz",
        "https://example.com/cb#%zz",
        "https://example.com/c\tb",
    ];
    for redirect_uri in not_absolute {
        let client = OAuthClient {
            redirect_uris: vec![redirect_uri.to_owned()],
            ..valid_public_client()
        };
        // Every recoverable field is broken too: the fatal check wins.
        let request = AuthorizeRequest {
            redirect_uri: redirect_uri.to_owned(),
            response_type: String::new(),
            state: String::new(),
            scope: String::new(),
            ..valid_request()
        };
        let error = expect_err(&FakeClients::with([client]), &request).await;
        assert_eq!(error, E::RedirectUriNotAbsolute, "{redirect_uri:?}");
        assert!(error.is_fatal());
    }
}

#[tokio::test]
async fn registered_absolute_redirect_uris_pass_go_url_parse() {
    let absolute = [
        "http://localhost:3000/callback",
        "http://127.0.0.1:8080/cb",
        "https://[::1]:8443/cb",
        "com.example.app://callback",
        "https://user:pass@example.com/cb",
        "https://example.com/c b",
        "https://example.com/cb?x=%zz",
        "https://例え.jp/cb",
        "https://example.com:/cb",
    ];
    for redirect_uri in absolute {
        let client = OAuthClient {
            redirect_uris: vec![redirect_uri.to_owned()],
            ..valid_public_client()
        };
        let request = AuthorizeRequest {
            redirect_uri: redirect_uri.to_owned(),
            ..valid_request()
        };
        expect_ok(&FakeClients::with([client]), &request).await;
    }
}

// ---------- check order ----------

#[tokio::test]
async fn fatal_checks_run_in_go_order() {
    let clients = repo();
    let empty = AuthorizeRequest::default();
    assert_eq!(expect_err(&clients, &empty).await, E::ClientIdRequired);

    // Unknown client beats a missing redirect_uri.
    let request = AuthorizeRequest {
        client_id: "nope".to_owned(),
        ..AuthorizeRequest::default()
    };
    assert_eq!(expect_err(&clients, &request).await, E::UnknownClient);

    // Inactive client beats a missing / mismatched redirect_uri.
    let inactive = FakeClients::with([OAuthClient {
        status: ClientStatus::parse("disabled"),
        ..valid_public_client()
    }]);
    for redirect_uri in ["", "https://evil.example.com/cb"] {
        let request = AuthorizeRequest {
            redirect_uri: redirect_uri.to_owned(),
            ..valid_request()
        };
        assert_eq!(expect_err(&inactive, &request).await, E::ClientNotActive);
    }

    // Missing redirect_uri even when the client registers "".
    let registers_empty = FakeClients::with([OAuthClient {
        redirect_uris: vec![String::new()],
        ..valid_public_client()
    }]);
    let request = AuthorizeRequest {
        redirect_uri: String::new(),
        ..valid_request()
    };
    assert_eq!(
        expect_err(&registers_empty, &request).await,
        E::RedirectUriRequired
    );
}

#[tokio::test]
async fn fatal_beats_every_recoverable_failure() {
    let broken = AuthorizeRequest {
        response_type: "token".to_owned(),
        state: String::new(),
        scope: "admin".to_owned(),
        nonce: String::new(),
        code_challenge: "x".to_owned(),
        code_challenge_method: "S128".to_owned(),
        ..valid_request()
    };
    let cases = [
        (
            AuthorizeRequest {
                redirect_uri: "https://evil.example.com/cb".to_owned(),
                ..broken.clone()
            },
            E::RedirectUriNotRegistered,
        ),
        (
            AuthorizeRequest {
                redirect_uri: String::new(),
                ..broken.clone()
            },
            E::RedirectUriRequired,
        ),
        (
            AuthorizeRequest {
                client_id: "nope".to_owned(),
                ..broken.clone()
            },
            E::UnknownClient,
        ),
    ];
    for (request, want) in cases {
        let error = expect_err(&repo(), &request).await;
        assert_eq!(error, want);
        assert!(error.is_fatal());
    }
    // With a good redirect_uri the first recoverable check reports.
    assert_eq!(
        expect_err(&repo(), &broken).await,
        E::UnsupportedResponseType
    );
}

#[tokio::test]
async fn recoverable_checks_run_in_go_order() {
    // Start fully broken and fix one field at a time: each step must report
    // the next check in Go's order.
    let mut request = AuthorizeRequest {
        response_type: String::new(),
        state: String::new(),
        scope: String::new(),
        nonce: String::new(),
        code_challenge: String::new(),
        code_challenge_method: "S128".to_owned(),
        ..valid_request()
    };
    let clients = repo();
    type Fix = fn(&mut AuthorizeRequest);
    let steps: [(ValidationError, Fix); 11] = [
        (E::ResponseTypeRequired, |r| {
            r.response_type = "id_token".to_owned();
        }),
        (E::UnsupportedResponseType, |r| {
            r.response_type = "code".to_owned();
        }),
        (E::StateRequired, |r| r.state = "s".to_owned()),
        (E::ScopeRequired, |r| r.scope = "openid admin".to_owned()),
        (E::ScopeNotAllowed, |r| r.scope = "openid".to_owned()),
        (E::NonceRequired, |r| r.nonce = "n".to_owned()),
        (E::CodeChallengeRequired, |r| {
            r.code_challenge = "a=".to_owned();
        }),
        (E::UnsupportedCodeChallengeMethod, |r| {
            r.code_challenge_method = "plain".to_owned();
        }),
        (E::PublicClientRequiresS256, |r| {
            r.code_challenge_method = "S256".to_owned();
        }),
        (E::CodeChallengeLength, |r| {
            r.code_challenge = "=".repeat(43);
        }),
        (E::CodeChallengeEncoding, |r| {
            r.code_challenge = VALID_CHALLENGE.to_owned();
        }),
    ];
    for (want, fix) in steps {
        let error = expect_err(&clients, &request).await;
        assert_eq!(error, want, "request {request:?}");
        assert!(error.is_recoverable());
        fix(&mut request);
    }
    expect_ok(&clients, &request).await;
}

#[tokio::test]
async fn response_type_is_exact() {
    for response_type in ["Code", "CODE", "code ", "code id_token", "token"] {
        let request = AuthorizeRequest {
            response_type: response_type.to_owned(),
            ..valid_request()
        };
        assert_eq!(
            expect_err(&repo(), &request).await,
            E::UnsupportedResponseType,
            "{response_type:?}"
        );
    }
}

// ---------- PKCE ----------

fn public_s256(challenge: &str) -> AuthorizeRequest {
    AuthorizeRequest {
        code_challenge: challenge.to_owned(),
        ..valid_request()
    }
}

#[tokio::test]
async fn pkce_length_bounds() {
    let clients = repo();
    for (len, want) in [
        (42, Some(E::CodeChallengeLength)),
        (43, None),
        (44, None),
        (127, None),
        (128, None),
        (129, Some(E::CodeChallengeLength)),
        (1, Some(E::CodeChallengeLength)),
    ] {
        let request = public_s256(&"a".repeat(len));
        let got = run(&clients, &request).await.err();
        // 45, 49, ... (len % 4 == 1) would fail decoding; 129 fails on length first.
        assert_eq!(got, want, "len {len}");
    }
}

#[tokio::test]
async fn pkce_length_counts_bytes() {
    // 42 ASCII bytes + one 2-byte char = 44 bytes: passes the length check,
    // then fails decoding.
    let request = public_s256(&("a".repeat(42) + "é"));
    assert_eq!(
        expect_err(&repo(), &request).await,
        E::CodeChallengeEncoding
    );
    // 65 two-byte chars is 130 bytes: too long, although only 65 chars.
    let request = public_s256(&"é".repeat(65));
    assert_eq!(expect_err(&repo(), &request).await, E::CodeChallengeLength);
}

#[tokio::test]
async fn pkce_encoding_rules() {
    let clients = repo();
    let a = |n: usize| "a".repeat(n);
    let cases: Vec<(String, Option<ValidationError>)> = vec![
        // Padding is rejected (unpadded encoding).
        (a(42) + "=", Some(E::CodeChallengeEncoding)),
        (a(43) + "=", Some(E::CodeChallengeEncoding)),
        (a(42) + "==", Some(E::CodeChallengeEncoding)),
        // Standard-alphabet and other characters are rejected.
        (a(42) + "+", Some(E::CodeChallengeEncoding)),
        (a(42) + "/", Some(E::CodeChallengeEncoding)),
        (a(42) + ".", Some(E::CodeChallengeEncoding)),
        (a(42) + "~", Some(E::CodeChallengeEncoding)),
        (a(21) + " " + &a(21), Some(E::CodeChallengeEncoding)),
        // A length of 4n+1 cannot be base64.
        (a(45), Some(E::CodeChallengeEncoding)),
        (a(125), Some(E::CodeChallengeEncoding)),
        // URL-safe alphabet, any remainder except 1.
        ("-_".repeat(22), None),
        ("_".repeat(128), None),
        (a(46), None),
        // Go's decoder is not strict: non-zero trailing bits pass.
        (a(42) + "B", None),
        // Go's decoder skips '\r' and '\n'; the length check counts them.
        (a(21) + "\n" + &a(22), None),
        (a(21) + "\r\n" + &a(22), None),
        // The RFC 7636 appendix B example.
        (
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_owned(),
            None,
        ),
    ];
    for (challenge, want) in cases {
        let got = run(&clients, &public_s256(&challenge)).await.err();
        assert_eq!(got, want, "challenge {challenge:?}");
    }
}

#[tokio::test]
async fn pkce_method_rules() {
    let clients = repo();

    // Method names are exact.
    for method in ["s256", "S-256", "PLAIN", "Plain", "none"] {
        let request = AuthorizeRequest {
            code_challenge_method: method.to_owned(),
            ..valid_request()
        };
        assert_eq!(
            expect_err(&clients, &request).await,
            E::UnsupportedCodeChallengeMethod,
            "public {method:?}"
        );
        let request = AuthorizeRequest {
            code_challenge_method: method.to_owned(),
            ..confidential_request()
        };
        assert_eq!(
            expect_err(&clients, &request).await,
            E::UnsupportedCodeChallengeMethod,
            "confidential {method:?}"
        );
    }

    // A challenge without a method means plain: public clients are refused.
    let request = AuthorizeRequest {
        code_challenge_method: String::new(),
        ..valid_request()
    };
    assert_eq!(
        expect_err(&clients, &request).await,
        E::PublicClientRequiresS256
    );

    // ...and confidential clients get the normalized method.
    let request = AuthorizeRequest {
        code_challenge_method: String::new(),
        ..confidential_request()
    };
    let v = expect_ok(&clients, &request).await;
    assert_eq!(v.request().code_challenge_method, "plain");

    // A method without a challenge: public clients still need a challenge.
    let request = AuthorizeRequest {
        code_challenge: String::new(),
        ..valid_request()
    };
    assert_eq!(
        expect_err(&clients, &request).await,
        E::CodeChallengeRequired
    );

    // Confidential clients skip every PKCE check without a challenge and the
    // method passes through unvalidated (Go behavior).
    for method in ["S256", "bogus"] {
        let request = AuthorizeRequest {
            code_challenge: String::new(),
            code_challenge_method: method.to_owned(),
            ..confidential_request()
        };
        let v = expect_ok(&clients, &request).await;
        assert_eq!(v.request().code_challenge_method, method);
    }

    // Confidential clients still get length and encoding checks.
    let request = AuthorizeRequest {
        code_challenge: "abc".to_owned(),
        ..confidential_request()
    };
    assert_eq!(expect_err(&clients, &request).await, E::CodeChallengeLength);
    let request = AuthorizeRequest {
        code_challenge: "a".repeat(42) + "=",
        code_challenge_method: "plain".to_owned(),
        ..confidential_request()
    };
    assert_eq!(
        expect_err(&clients, &request).await,
        E::CodeChallengeEncoding
    );
}

#[tokio::test]
async fn unknown_client_type_is_treated_as_confidential() {
    // Go compares ClientType == "public"; anything else skips public rules.
    let client = OAuthClient {
        client_type: ClientType::parse("Public"),
        ..valid_public_client()
    };
    let request = AuthorizeRequest {
        code_challenge: String::new(),
        code_challenge_method: String::new(),
        ..valid_request()
    };
    expect_ok(&FakeClients::with([client]), &request).await;
}

// ---------- scopes ----------

#[tokio::test]
async fn scopes_match_golden_oauth_splitter() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../testdata/golden/scopes.json"
    );
    let raw = std::fs::read_to_string(path).expect("read scopes.json");
    let golden: serde_json::Value = serde_json::from_str(&raw).expect("parse scopes.json");
    let cases = golden["oauth_split_scopes"]["cases"]
        .as_array()
        .expect("oauth_split_scopes cases");
    assert!(!cases.is_empty());

    for case in cases {
        let input = case["input"].as_str().expect("input");
        let joined = case["joined"].as_str().expect("joined");
        let output: Vec<&str> = case["output"]
            .as_array()
            .map(|items| items.iter().map(|s| s.as_str().expect("item")).collect())
            .unwrap_or_default();

        // The same splitter parses the client's allowed scopes.
        let clients = FakeClients::with([OAuthClient {
            allowed_scopes: input.to_owned(),
            ..valid_confidential_client()
        }]);
        let request = AuthorizeRequest {
            scope: input.to_owned(),
            ..confidential_request()
        };
        if output.is_empty() {
            assert_eq!(
                expect_err(&clients, &request).await,
                E::ScopeRequired,
                "input {input:?}"
            );
            continue;
        }
        let v = expect_ok(&clients, &request).await;
        let got: Vec<&str> = v.scopes().iter().map(String::as_str).collect();
        assert_eq!(got, output, "input {input:?}");
        assert_eq!(v.request().scope, joined, "input {input:?}");
    }
}

#[tokio::test]
async fn scope_edge_cases() {
    let clients = repo();
    let check = |scope: &str| AuthorizeRequest {
        scope: scope.to_owned(),
        ..valid_request()
    };

    // Only separators: no scopes.
    for scope in [" ", " , ,\n\t", ","] {
        assert_eq!(
            expect_err(&clients, &check(scope)).await,
            E::ScopeRequired,
            "{scope:?}"
        );
    }
    // Comma separated, duplicated, unordered.
    let v = expect_ok(&clients, &check("profile,openid,openid\temail")).await;
    assert_eq!(v.request().scope, "email openid profile");
    // A subset is enough.
    let v = expect_ok(&clients, &check("email")).await;
    assert_eq!(v.request().scope, "email");
    // Case-sensitive membership.
    assert_eq!(
        expect_err(&clients, &check("openid Email")).await,
        E::ScopeNotAllowed
    );
    // `\r` and NBSP do not split, so the item is not allowed.
    for scope in ["openid\remail", "openid\u{a0}email"] {
        assert_eq!(
            expect_err(&clients, &check(scope)).await,
            E::ScopeNotAllowed,
            "{scope:?}"
        );
    }
    // But they are trimmed at item edges.
    let v = expect_ok(&clients, &check("openid\r email\u{a0}")).await;
    assert_eq!(v.request().scope, "email openid");
}

#[tokio::test]
async fn allowed_scopes_use_the_oauth_splitter() {
    let client = OAuthClient {
        allowed_scopes: "openid,email\nprofile\toffline_access".to_owned(),
        ..valid_public_client()
    };
    let request = AuthorizeRequest {
        scope: "offline_access profile email openid".to_owned(),
        ..valid_request()
    };
    let v = expect_ok(&FakeClients::with([client]), &request).await;
    assert_eq!(v.request().scope, "email offline_access openid profile");

    let client = OAuthClient {
        allowed_scopes: String::new(),
        ..valid_public_client()
    };
    assert_eq!(
        expect_err(&FakeClients::with([client]), &valid_request()).await,
        E::ScopeNotAllowed
    );
}

#[tokio::test]
async fn nonce_is_only_required_for_exact_openid() {
    let client = OAuthClient {
        allowed_scopes: "openid OpenID email".to_owned(),
        ..valid_public_client()
    };
    let clients = FakeClients::with([client]);
    for (scope, want) in [
        ("email", None),
        ("OpenID email", None),
        ("openid", Some(E::NonceRequired)),
        ("email,openid", Some(E::NonceRequired)),
    ] {
        let request = AuthorizeRequest {
            scope: scope.to_owned(),
            nonce: String::new(),
            ..valid_request()
        };
        assert_eq!(run(&clients, &request).await.err(), want, "{scope:?}");
    }
}

// ---------- output ----------

#[tokio::test]
async fn validated_passes_other_fields_through_untouched() {
    let request = AuthorizeRequest {
        state: " xyz ".to_owned(),
        nonce: " n ".to_owned(),
        prompt: "login".to_owned(),
        scope: " profile openid ".to_owned(),
        ..valid_request()
    };
    let v = expect_ok(&repo(), &request).await;
    let want = AuthorizeRequest {
        scope: "openid profile".to_owned(),
        ..request
    };
    assert_eq!(v.request(), &want);
    assert_eq!(
        v.client().redirect_uris,
        valid_public_client().redirect_uris
    );

    let (client, scopes, canonical) = v.into_parts();
    assert_eq!(client.client_id, "trading-web");
    assert_eq!(scopes.to_string(), "openid profile");
    assert_eq!(canonical, want);
}

#[tokio::test]
async fn validator_service_uses_the_port() {
    let validator = AuthorizeRequestValidator::new(Arc::new(repo()));
    let v = validator
        .validate(&valid_request())
        .await
        .expect("valid request");
    assert_eq!(v.client().client_id, "trading-web");

    let error = validator
        .validate(&AuthorizeRequest::default())
        .await
        .expect_err("empty request");
    assert_eq!(error, E::ClientIdRequired);
}
