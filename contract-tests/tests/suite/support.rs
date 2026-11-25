use std::{collections::BTreeMap, env};

use auth_contract_tests::{base_url, http_client, json_response, setting};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use reqwest::{Client, RequestBuilder, Response, StatusCode, header};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use url::{Url, form_urlencoded};
use uuid::Uuid;

pub const AUTHORIZE: &str = "/v1/oauth2/authorize";
pub const TOKEN: &str = "/v1/oauth2/token";
pub const REVOKE: &str = "/v1/oauth2/revoke";
pub const INTROSPECT: &str = "/v1/oauth2/introspect";
pub const USERINFO: &str = "/v1/oidc/userinfo";
pub const OTP_START: &str = "/v1/auth/otp/start";
pub const OTP_VERIFY: &str = "/v1/auth/otp/verify";
pub const CONSENT_ACCEPT: &str = "/v1/auth/consent/accept";
pub const SSO: &str = "auth_sso_session";
pub const CSRF: &str = "auth_csrf";
pub const FULL_SCOPE: &str = "email openid profile";
pub type Params = BTreeMap<String, String>;

pub struct Api {
    http: Client,
    pub base: String,
    pub ui: String,
    pub issuer: String,
    pub audience: String,
    pub browser: OAuthClient,
    pub web: OAuthClient,
    pub worker: OAuthClient,
}

pub struct OAuthClient {
    pub id: String,
    pub secret: Option<String>,
    pub redirect_uri: String,
}

impl Api {
    pub fn new() -> Self {
        let base = base_url();
        Self {
            http: http_client(),
            issuer: setting("CONTRACT_ISSUER", &base),
            audience: setting("CONTRACT_AUDIENCE", "platform-api"),
            ui: setting("AUTH_UI_BASE_URL", "http://localhost:3005")
                .trim_end_matches('/')
                .into(),
            browser: OAuthClient {
                id: setting("CONTRACT_BROWSER_CLIENT_ID", "dev-browser"),
                secret: None,
                redirect_uri: setting(
                    "CONTRACT_BROWSER_REDIRECT_URI",
                    "http://localhost:8050/dev/callback",
                ),
            },
            web: OAuthClient {
                id: setting("CONTRACT_WEB_CLIENT_ID", "community-web"),
                secret: Some(setting(
                    "CONTRACT_WEB_CLIENT_SECRET",
                    "community-web-secret",
                )),
                redirect_uri: setting(
                    "CONTRACT_WEB_REDIRECT_URI",
                    "http://localhost:3006/api/auth/oauth2/callback/auth-server",
                ),
            },
            worker: OAuthClient {
                id: setting("CONTRACT_WORKER_CLIENT_ID", "dev-worker"),
                secret: Some(setting(
                    "CONTRACT_WORKER_CLIENT_SECRET",
                    "dev-worker-secret",
                )),
                redirect_uri: String::new(),
            },
            base,
        }
    }

    pub fn get(&self, path: &str) -> RequestBuilder {
        self.http.get(format!("{}{path}", self.base))
    }

    pub fn get_with_query<K: AsRef<str>, V: AsRef<str>>(
        &self,
        path: &str,
        pairs: impl IntoIterator<Item = (K, V)>,
    ) -> RequestBuilder {
        self.get(&format!("{path}?{}", encoded_query(pairs)))
    }

    pub fn post(&self, path: &str) -> RequestBuilder {
        self.http.post(format!("{}{path}", self.base))
    }

    pub fn form(
        &self,
        path: &str,
        client: &OAuthClient,
        auth: ClientAuth,
        fields: &[(&str, &str)],
    ) -> RequestBuilder {
        let mut fields = fields.to_vec();
        let mut request = self.post(path);
        match auth {
            ClientAuth::Post => {
                fields.push(("client_id", &client.id));
                if let Some(secret) = &client.secret {
                    fields.push(("client_secret", secret));
                }
            }
            ClientAuth::Basic => {
                request = request.basic_auth(&client.id, Some(client.secret.as_deref().unwrap()));
            }
        }
        request.form(&fields)
    }

    pub fn authorize(&self, params: &Params) -> RequestBuilder {
        self.get_with_query(AUTHORIZE, params)
    }

    pub fn ui_route(&self, path: &str, params: &Params) -> String {
        format!("{}{path}?{}", self.ui, encoded_query(params))
    }

    pub fn support_token() -> String {
        required("CONTRACT_SUPPORT_TOKEN")
    }

    pub async fn summary(&self, sub: &str) -> Value {
        response_json(
            self.get(&format!("/v1/support/accounts/{sub}"))
                .bearer_auth(Self::support_token()),
            StatusCode::OK,
        )
        .await
    }

    pub async fn refresh(&self, client: &OAuthClient, token: &str) -> Response {
        send(self.form(
            TOKEN,
            client,
            ClientAuth::Post,
            &[("grant_type", "refresh_token"), ("refresh_token", token)],
        ))
        .await
    }
}

#[derive(Clone, Copy)]
pub enum ClientAuth {
    Basic,
    Post,
}

pub struct Flow {
    pub params: Params,
    pub verifier: String,
}

impl Flow {
    pub fn new(client: &OAuthClient, scope: &str) -> Self {
        let verifier = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        let params = [
            ("client_id", client.id.clone()),
            ("redirect_uri", client.redirect_uri.clone()),
            ("response_type", "code".into()),
            ("scope", scope.into()),
            ("state", "contract +&~*".into()),
            ("nonce", Uuid::new_v4().to_string()),
            (
                "code_challenge",
                URL_SAFE_NO_PAD.encode(Sha256::digest(&verifier)),
            ),
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

    pub fn body(&self, fields: &[(&str, &str)]) -> Value {
        let mut body = json!(self.params);
        let object = body.as_object_mut().unwrap();
        object.extend(
            fields
                .iter()
                .map(|(key, value)| ((*key).into(), json!(value))),
        );
        body
    }

    pub fn exchange(
        &self,
        api: &Api,
        client: &OAuthClient,
        code: &str,
        verifier: &str,
    ) -> RequestBuilder {
        api.form(
            TOKEN,
            client,
            ClientAuth::Post,
            &[
                ("grant_type", "authorization_code"),
                ("redirect_uri", &self.params["redirect_uri"]),
                ("code", code),
                ("code_verifier", verifier),
            ],
        )
    }

    pub fn callback(&self, updates: &[(&str, &str)]) -> String {
        let mut url = Url::parse(&self.params["redirect_uri"]).expect("registered callback URL");
        let mut query = BTreeMap::<String, Vec<String>>::new();
        for (name, value) in url.query_pairs() {
            query
                .entry(name.into_owned())
                .or_default()
                .push(value.into_owned());
        }
        for (key, value) in updates {
            query.insert((*key).into(), vec![(*value).into()]);
        }
        let pairs = query
            .iter()
            .flat_map(|(key, values)| values.iter().map(move |v| (key, v)));
        url.set_query(Some(&encoded_query(pairs)));
        url.into()
    }

    pub fn assert_error_redirect(&self, location: &str, error: &str, description: &str) {
        let mut updates = vec![("error", error), ("error_description", description)];
        if let Some(state) = self.params.get("state").filter(|state| !state.is_empty()) {
            updates.push(("state", state));
        }
        assert_eq!(location, self.callback(&updates));
    }

    pub fn code(&self, location: &str) -> String {
        let url = Url::parse(location).expect("authorization callback URL");
        let code = url
            .query_pairs()
            .find(|(key, _)| key == "code")
            .expect("authorization code in redirect")
            .1
            .into_owned();
        assert_opaque(&code);
        assert_eq!(
            location,
            self.callback(&[("code", &code), ("state", &self.params["state"])])
        );
        code
    }
}

#[derive(Default)]
pub struct Browser {
    pub sso: Option<String>,
    pub csrf: Option<String>,
}

impl Browser {
    pub fn request(&self, request: RequestBuilder) -> RequestBuilder {
        let cookies = [(SSO, &self.sso), (CSRF, &self.csrf)]
            .into_iter()
            .filter_map(|(key, value)| value.as_ref().map(|value| format!("{key}={value}")))
            .collect::<Vec<_>>();
        if cookies.is_empty() {
            request
        } else {
            request.header(header::COOKIE, cookies.join("; "))
        }
    }

    pub async fn fetch_csrf(&mut self, api: &Api) {
        let response = send(self.request(api.get("/v1/auth/csrf"))).await;
        let (value, attrs) = cookie(&response, CSRF);
        assert_cookie_attributes(attrs, false, Some("1800".into()));
        assert_opaque(&value);
        assert_eq!(
            json_response(response, StatusCode::OK).await,
            json!({"csrf_token": value, "expires_in": 1800})
        );
        self.csrf = Some(value);
    }

    pub async fn verify_otp(&mut self, api: &Api, flow: &Flow, email: &str) -> Value {
        let challenge = otp_start(api, flow, email).await;
        let response =
            send(self.request(otp_verify(api, flow, email, &challenge, &otp_code()))).await;
        let (value, attrs) = cookie(&response, SSO);
        assert_uuid_v7(&value);
        let max_age = attrs.get("max-age").expect("SSO Max-Age").as_str();
        let age = max_age.parse::<u64>().expect("SSO Max-Age seconds");
        assert!((2_591_990..=2_592_000).contains(&age), "SSO Max-Age: {age}");
        assert_cookie_attributes(attrs.clone(), true, Some(max_age.into()));
        let result = json_response(response, StatusCode::OK).await;
        assert_keys(&result, &["account", "redirect_to"]);
        let account = &result["account"];
        assert_keys(account, &["display_name", "email", "id"]);
        assert_uuid_v7(string(account, "id"));
        assert_eq!(account["email"], email);
        assert_eq!(account["display_name"], email.split_once('@').unwrap().0);
        self.sso = Some(value);
        result
    }

    pub async fn accept(&self, api: &Api, flow: &Flow) -> String {
        let body = flow.body(&[("csrf_token", self.csrf.as_deref().unwrap())]);
        let result = response_json(
            self.request(api.post(CONSENT_ACCEPT).json(&body)),
            StatusCode::OK,
        )
        .await;
        assert_keys(&result, &["redirect_to"]);
        flow.code(string(&result, "redirect_to"))
    }
}

pub struct Login {
    pub email: String,
    pub sub: String,
    pub tokens: Value,
}

impl Login {
    pub fn refresh_token(&self) -> &str {
        string(&self.tokens, "refresh_token")
    }
}

pub async fn login(api: &Api, browser: &mut Browser, client: &OAuthClient, scope: &str) -> Login {
    browser.fetch_csrf(api).await;
    let flow = Flow::new(client, scope);
    let email = unique_email();
    let result = browser.verify_otp(api, &flow, &email).await;
    assert_consent_redirect(api, &flow, &result);
    let code = browser.accept(api, &flow).await;
    let tokens = response_json(
        flow.exchange(api, client, &code, &flow.verifier),
        StatusCode::OK,
    )
    .await;
    Login {
        email,
        sub: string(&result["account"], "id").into(),
        tokens,
    }
}

pub fn assert_consent_redirect(api: &Api, flow: &Flow, result: &Value) {
    let mut params = flow.params.clone();
    let mut scopes: Vec<_> = flow.params["scope"].split_whitespace().collect();
    scopes.sort_unstable();
    scopes.dedup();
    params.insert("scope".into(), scopes.join(" "));
    assert_eq!(result["redirect_to"], api.ui_route("/consent", &params));
}

pub async fn otp_start(api: &Api, flow: &Flow, email: &str) -> String {
    let result = response_json(
        api.post(OTP_START).json(&flow.body(&[("email", email)])),
        StatusCode::OK,
    )
    .await;
    assert_keys(
        &result,
        &["email", "expires_at", "otp_challenge_id", "redirect_to"],
    );
    let challenge = string(&result, "otp_challenge_id");
    assert_uuid_v7(challenge);
    assert_timestamp(&result, "expires_at");
    let (local, domain) = email.split_once('@').unwrap();
    let masked = format!(
        "{}{}{}@{domain}",
        &local[..1],
        "*".repeat(local.len() - 2),
        &local[local.len() - 1..]
    );
    assert_eq!(result["email"], masked);
    let mut params = flow.params.clone();
    params.insert("otp_challenge_id".into(), challenge.into());
    params.insert("email".into(), email.into());
    assert_eq!(result["redirect_to"], api.ui_route("/otp", &params));
    challenge.into()
}

pub fn otp_verify(
    api: &Api,
    flow: &Flow,
    email: &str,
    challenge: &str,
    code: &str,
) -> RequestBuilder {
    api.post(OTP_VERIFY).json(&flow.body(&[
        ("email", email),
        ("otp_challenge_id", challenge),
        ("code", code),
    ]))
}

pub fn otp_code() -> String {
    required("CONTRACT_OTP_CODE")
}

pub fn unique_email() -> String {
    format!("contract-{}@example.test", Uuid::new_v4().simple())
}

pub fn required(key: &str) -> String {
    env::var(key).unwrap_or_else(|_| panic!("{key} must be set for this test"))
}

pub async fn send(request: RequestBuilder) -> Response {
    request
        .send()
        .await
        .expect("send HTTP request to auth server")
}

pub async fn response_json(request: RequestBuilder, status: StatusCode) -> Value {
    json_response(send(request).await, status).await
}

pub async fn assert_error(
    response: Response,
    status: StatusCode,
    error: &str,
    description: Option<&str>,
) {
    let expected = match description {
        Some(description) => json!({"error": error, "error_description": description}),
        None => json!({"error": error}),
    };
    assert_eq!(json_response(response, status).await, expected);
}

pub fn location(response: &Response) -> &str {
    assert_eq!(
        response.status(),
        StatusCode::FOUND,
        "{}",
        response.url().path()
    );
    header_value(response, "location")
}

pub fn header_value<'a>(response: &'a Response, name: &str) -> &'a str {
    response
        .headers()
        .get(name)
        .unwrap_or_else(|| panic!("missing {name} header"))
        .to_str()
        .expect("ASCII response header")
}

pub fn encoded_query<K: AsRef<str>, V: AsRef<str>>(
    pairs: impl IntoIterator<Item = (K, V)>,
) -> String {
    // OAuth redirects use RFC 3986's unreserved characters and '+' for spaces.
    form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs)
        .finish()
        .replace("%7E", "~")
        .replace('*', "%2A")
}

pub fn cookie(response: &Response, expected_name: &str) -> (String, Params) {
    let headers = response.headers().get_all(header::SET_COOKIE);
    let mut headers = headers.iter();
    let mut parts = headers
        .next()
        .expect("Set-Cookie header")
        .to_str()
        .unwrap()
        .split(';');
    assert!(
        headers.next().is_none(),
        "expected exactly one Set-Cookie header"
    );
    let (name, value) = parts
        .next()
        .unwrap()
        .split_once('=')
        .expect("cookie name and value");
    assert_eq!(name, expected_name);
    let mut attrs = Params::new();
    for part in parts {
        let (key, value) = part.trim().split_once('=').unwrap_or((part.trim(), ""));
        assert!(
            attrs
                .insert(key.to_ascii_lowercase(), value.into())
                .is_none(),
            "duplicate cookie attribute {key}"
        );
    }
    (value.into(), attrs)
}

pub fn assert_cookie_attributes(attrs: Params, http_only: bool, max_age: Option<String>) {
    let mut expected = Params::from([
        ("path".into(), "/".into()),
        (
            "samesite".into(),
            setting("CONTRACT_COOKIE_SAME_SITE", "Lax"),
        ),
    ]);
    if let Some(max_age) = max_age {
        expected.insert("max-age".into(), max_age);
    }
    if http_only {
        expected.insert("httponly".into(), String::new());
    }
    if setting("CONTRACT_COOKIE_SECURE", "false")
        .parse()
        .expect("boolean cookie setting")
    {
        expected.insert("secure".into(), String::new());
    }
    let domain = setting("CONTRACT_COOKIE_DOMAIN", "");
    if !domain.is_empty() {
        expected.insert("domain".into(), domain);
    }
    assert_eq!(attrs, expected);
}

pub fn assert_keys(value: &Value, keys: &[&str]) {
    let map = value.as_object().expect("JSON object");
    let mut expected = keys.to_vec();
    expected.sort_unstable();
    assert_eq!(map.keys().map(String::as_str).collect::<Vec<_>>(), expected);
}

pub fn string<'a>(value: &'a Value, name: &str) -> &'a str {
    value[name]
        .as_str()
        .unwrap_or_else(|| panic!("missing string field {name}"))
}

pub fn integer(value: &Value, name: &str) -> i64 {
    value[name]
        .as_i64()
        .unwrap_or_else(|| panic!("missing integer field {name}"))
}

pub fn assert_uuid_v7(value: &str) {
    assert_eq!(Uuid::parse_str(value).expect("UUID").get_version_num(), 7);
}

pub fn assert_timestamp(value: &Value, key: &str) {
    let value = string(value, key);
    let bytes = value.as_bytes();
    assert!(
        bytes.len() >= 20
            && bytes[4] == b'-'
            && bytes[7] == b'-'
            && bytes[10] == b'T'
            && bytes[13] == b':'
            && bytes[16] == b':'
            && (value.ends_with('Z') || value[19..].contains(['+', '-'])),
        "{key}: expected RFC 3339 timestamp, got {value}"
    );
}

pub fn assert_opaque(value: &str) {
    assert_eq!(
        URL_SAFE_NO_PAD
            .decode(value)
            .expect("base64url unpadded")
            .len(),
        32
    );
}
