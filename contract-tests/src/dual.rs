//! Raw HTTP helpers for tests that drive the Go and Rust servers side by side
//! (differential and continuity runs). Unlike the contract suite these helpers
//! never assert: they return the raw reply so the caller can record or check it.

use std::collections::BTreeMap;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use reqwest::{Client, Method, RequestBuilder, header};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use url::{Url, form_urlencoded};

use crate::{http_client, setting};

pub const AUTHORIZE: &str = "/v1/oauth2/authorize";
pub const TOKEN: &str = "/v1/oauth2/token";
pub const REVOKE: &str = "/v1/oauth2/revoke";
pub const INTROSPECT: &str = "/v1/oauth2/introspect";
pub const USERINFO: &str = "/v1/oidc/userinfo";
pub const SSO: &str = "auth_sso_session";
pub const CSRF: &str = "auth_csrf";
pub const FULL_SCOPE: &str = "email openid profile";

pub type Params = BTreeMap<String, String>;

/// Client fixtures shared with `run-local.sh` and the dual-server harness.
pub struct Fixtures {
    pub ui: String,
    pub issuer: String,
    pub audience: String,
    pub otp_code: String,
    pub support_token: String,
    pub hint_email: String,
    pub logout_redirect: String,
    pub browser: OAuthClient,
    pub web: OAuthClient,
    pub worker: OAuthClient,
    pub inactive_client: String,
    pub malformed_client: String,
    pub malformed_redirect: String,
}

#[derive(Clone)]
pub struct OAuthClient {
    pub id: String,
    pub secret: Option<String>,
    pub redirect_uri: String,
}

impl Fixtures {
    pub fn from_env() -> Self {
        let required = |key: &str| {
            std::env::var(key).unwrap_or_else(|_| panic!("{key} must be set for this test"))
        };
        Self {
            ui: setting("AUTH_UI_BASE_URL", "http://localhost:3005")
                .trim_end_matches('/')
                .into(),
            issuer: required("CONTRACT_ISSUER"),
            audience: setting("CONTRACT_AUDIENCE", "platform-api"),
            otp_code: required("CONTRACT_OTP_CODE"),
            support_token: required("CONTRACT_SUPPORT_TOKEN"),
            hint_email: setting("CONTRACT_HINT_EMAIL", "contract-hint@example.test"),
            logout_redirect: required("CONTRACT_LOGOUT_REDIRECT_URI"),
            browser: OAuthClient {
                id: setting("CONTRACT_BROWSER_CLIENT_ID", "dev-browser"),
                secret: None,
                redirect_uri: required("CONTRACT_BROWSER_REDIRECT_URI"),
            },
            web: OAuthClient {
                id: setting("CONTRACT_WEB_CLIENT_ID", "community-web"),
                secret: Some(required("CONTRACT_WEB_CLIENT_SECRET")),
                redirect_uri: required("CONTRACT_WEB_REDIRECT_URI"),
            },
            worker: OAuthClient {
                id: setting("CONTRACT_WORKER_CLIENT_ID", "dev-worker"),
                secret: Some(required("CONTRACT_WORKER_CLIENT_SECRET")),
                redirect_uri: String::new(),
            },
            inactive_client: setting("CONTRACT_INACTIVE_CLIENT_ID", "knowledge-web"),
            malformed_client: setting("CONTRACT_MALFORMED_CLIENT_ID", "language-web"),
            malformed_redirect: setting("CONTRACT_MALFORMED_REDIRECT_URI", "/contract-callback"),
        }
    }
}

/// One running server.
pub struct Target {
    pub name: &'static str,
    pub base: String,
    http: Client,
}

impl Target {
    pub fn new(name: &'static str, base: &str) -> Self {
        Self {
            name,
            base: base.trim_end_matches('/').into(),
            http: http_client(),
        }
    }

    pub fn request(&self, method: Method, path: &str) -> RequestBuilder {
        self.http.request(method, format!("{}{path}", self.base))
    }

    pub fn get(&self, path: &str) -> RequestBuilder {
        self.request(Method::GET, path)
    }

    pub fn post(&self, path: &str) -> RequestBuilder {
        self.request(Method::POST, path)
    }

    pub fn get_query<K: AsRef<str>, V: AsRef<str>>(
        &self,
        path: &str,
        pairs: impl IntoIterator<Item = (K, V)>,
    ) -> RequestBuilder {
        self.get(&format!("{path}?{}", encoded_query(pairs)))
    }

    pub fn authorize(&self, params: &Params) -> RequestBuilder {
        self.get_query(AUTHORIZE, params)
    }

    /// Form POST with client authentication in the body (`Post`) or HTTP Basic.
    pub fn form(
        &self,
        path: &str,
        client: &OAuthClient,
        basic: bool,
        fields: &[(&str, &str)],
    ) -> RequestBuilder {
        let mut fields = fields.to_vec();
        let mut request = self.post(path);
        if basic {
            request = request.basic_auth(&client.id, client.secret.as_deref());
        } else {
            fields.push(("client_id", &client.id));
            if let Some(secret) = &client.secret {
                fields.push(("client_secret", secret));
            }
        }
        request.form(&fields)
    }

    pub fn exchange(
        &self,
        client: &OAuthClient,
        flow: &Flow,
        code: &str,
        verifier: &str,
    ) -> RequestBuilder {
        self.form(
            TOKEN,
            client,
            false,
            &[
                ("grant_type", "authorization_code"),
                ("redirect_uri", &flow.params["redirect_uri"]),
                ("code", code),
                ("code_verifier", verifier),
            ],
        )
    }

    pub fn refresh(&self, client: &OAuthClient, token: &str) -> RequestBuilder {
        self.form(
            TOKEN,
            client,
            false,
            &[("grant_type", "refresh_token"), ("refresh_token", token)],
        )
    }

    pub fn introspect(&self, worker: &OAuthClient, token: &str, hint: &str) -> RequestBuilder {
        self.form(
            INTROSPECT,
            worker,
            true,
            &[("token", token), ("token_type_hint", hint)],
        )
    }
}

/// A fully read HTTP response.
#[derive(Clone, Debug)]
pub struct Reply {
    pub status: u16,
    pub headers: header::HeaderMap,
    pub body: Vec<u8>,
}

impl Reply {
    pub async fn send(request: RequestBuilder) -> Self {
        let response = request
            .send()
            .await
            .expect("send HTTP request to auth server");
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let body = response
            .bytes()
            .await
            .expect("read HTTP response body")
            .to_vec();
        Self {
            status,
            headers,
            body,
        }
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|value| value.to_str().ok())
    }

    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }

    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    /// `body[key]` as a string, or empty.
    pub fn field(&self, key: &str) -> String {
        self.json()[key].as_str().unwrap_or_default().into()
    }

    pub fn location(&self) -> String {
        self.header("location").unwrap_or_default().into()
    }

    /// Every `Set-Cookie` as (name, value, lower-cased attributes).
    pub fn cookies(&self) -> Vec<(String, String, Params)> {
        self.headers
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .map(parse_set_cookie)
            .collect()
    }
}

pub fn parse_set_cookie(raw: &str) -> (String, String, Params) {
    let mut parts = raw.split(';');
    let (name, value) = parts
        .next()
        .unwrap_or_default()
        .split_once('=')
        .unwrap_or_default();
    let attrs = parts
        .map(|part| {
            let (key, value) = part.trim().split_once('=').unwrap_or((part.trim(), ""));
            (key.to_ascii_lowercase(), value.to_owned())
        })
        .collect();
    (name.trim().into(), value.into(), attrs)
}

/// SSO + CSRF cookies of one simulated browser.
#[derive(Clone, Default, Debug)]
pub struct Jar {
    pub sso: Option<String>,
    pub csrf: Option<String>,
}

impl Jar {
    pub fn apply(&self, request: RequestBuilder) -> RequestBuilder {
        let cookies: Vec<_> = [(SSO, &self.sso), (CSRF, &self.csrf)]
            .into_iter()
            .filter_map(|(key, value)| value.as_ref().map(|value| format!("{key}={value}")))
            .collect();
        if cookies.is_empty() {
            request
        } else {
            request.header(header::COOKIE, cookies.join("; "))
        }
    }

    /// Track cookies the way a browser would: set, or delete on an empty
    /// value or a non-positive `Max-Age`.
    pub fn absorb(&mut self, reply: &Reply) {
        for (name, value, attrs) in reply.cookies() {
            let expired = value.is_empty()
                || attrs
                    .get("max-age")
                    .and_then(|age| age.parse::<i64>().ok())
                    .is_some_and(|age| age <= 0);
            let slot = match name.as_str() {
                SSO => &mut self.sso,
                CSRF => &mut self.csrf,
                _ => continue,
            };
            *slot = (!expired).then_some(value);
        }
    }
}

/// A deterministic authorization request: the same `seed` gives the same
/// nonce, verifier and challenge on every server, so redirects compare equal.
pub struct Flow {
    pub params: Params,
    pub verifier: String,
}

impl Flow {
    pub fn new(client: &OAuthClient, scope: &str, seed: &str) -> Self {
        let verifier = format!("{seed}-verifier-{}", "v".repeat(48));
        let params = [
            ("client_id", client.id.clone()),
            ("redirect_uri", client.redirect_uri.clone()),
            ("response_type", "code".into()),
            ("scope", scope.into()),
            ("state", "contract +&~*".into()),
            ("nonce", format!("{seed}-nonce")),
            ("code_challenge", challenge(&verifier)),
            ("code_challenge_method", "S256".into()),
        ]
        .into_iter()
        .map(|(key, value)| (key.into(), value))
        .collect();
        Self { params, verifier }
    }

    pub fn prompt(mut self, prompt: &str) -> Self {
        self.params.insert("prompt".into(), prompt.into());
        self
    }

    pub fn with(mut self, key: &str, value: &str) -> Self {
        self.params.insert(key.into(), value.into());
        self
    }

    /// The OAuth params as a JSON action body plus extra fields.
    pub fn body(&self, fields: &[(&str, &str)]) -> Value {
        let mut body = json!(self.params);
        let object = body.as_object_mut().expect("object body");
        for (key, value) in fields {
            object.insert((*key).into(), json!(value));
        }
        body
    }
}

pub fn challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier))
}

/// The `code` query parameter of an authorization redirect, or empty.
pub fn code_from(location: &str) -> String {
    query_param(location, "code")
}

pub fn query_param(location: &str, key: &str) -> String {
    Url::parse(location)
        .ok()
        .and_then(|url| {
            url.query_pairs()
                .find(|(name, _)| name == key)
                .map(|(_, value)| value.into_owned())
        })
        .unwrap_or_default()
}

/// OAuth redirects use RFC 3986's unreserved characters and '+' for spaces.
pub fn encoded_query<K: AsRef<str>, V: AsRef<str>>(
    pairs: impl IntoIterator<Item = (K, V)>,
) -> String {
    form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs)
        .finish()
        .replace("%7E", "~")
        .replace('*', "%2A")
}
