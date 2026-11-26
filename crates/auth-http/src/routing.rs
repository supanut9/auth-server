//! gin v1.12 routing behaviour on top of axum.
//!
//! Routes are registered with gin path syntax (`/v1/clients/:clientID/...`)
//! so the router can reproduce gin's dispatch, which axum does differently:
//!
//! - Matching is per method on the decoded path (Go `URL.Path`). There is no
//!   implicit `HEAD` for `GET` and never a 405: a known path with another
//!   method, like an unknown path, goes to the "no route" chain, which runs
//!   the global middleware and then answers `404` `text/plain`
//!   `404 page not found`.
//! - When the method has routes, the path is not `/` and toggling its
//!   trailing slash matches a route of the same method, gin redirects
//!   (`301` for `GET`, `307` otherwise) *before* any middleware: no
//!   `X-Request-Id`, no access-log line, no CORS headers. The `Location`
//!   honours `X-Forwarded-Prefix` and is built exactly as gin's
//!   `redirectTrailingSlash` + Go `http.Redirect` build it.
//! - Matched requests carry a [`FullPath`] extension (gin `c.FullPath()`).

use std::{convert::Infallible, sync::Arc};

use axum::{
    Router,
    body::Body,
    extract::{FromRequestParts, Request, State},
    handler::Handler,
    http::{HeaderValue, Method, StatusCode, header, request::Parts},
    response::Response,
    routing::{MethodRouter, on},
};
use tower::Service;

use crate::{go_url, middleware::GlobalLayers};

/// gin's `default404Body`.
pub const NOT_FOUND_BODY: &str = "404 page not found";

/// The matched route pattern in gin syntax (gin `c.FullPath()`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FullPath(Arc<str>);

impl FullPath {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<S: Send + Sync> FromRequestParts<S> for FullPath {
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(parts.extensions.get::<Self>().cloned().unwrap_or_default())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Segment {
    Static(String),
    Param,
}

#[derive(Debug, Clone)]
struct Route {
    method: Method,
    segments: Vec<Segment>,
    pattern: Arc<str>,
}

impl Route {
    fn matches(&self, path_segments: &[&str]) -> bool {
        self.segments.len() == path_segments.len()
            && self
                .segments
                .iter()
                .zip(path_segments)
                .all(|(segment, value)| match segment {
                    Segment::Static(expected) => expected == value,
                    // Deviation: gin binds an empty value (`/v1/clients//x`
                    // reaches the handler with `clientID=""`); axum cannot
                    // route an empty segment, so it is a 404 here.
                    Segment::Param => !value.is_empty(),
                })
    }

    /// Static segments outrank parameters, like gin's tree and axum's
    /// matcher.
    fn priority(&self) -> Vec<bool> {
        self.segments
            .iter()
            .map(|segment| matches!(segment, Segment::Static(_)))
            .collect()
    }
}

#[derive(Debug, Clone, Default)]
struct RouteTable {
    routes: Vec<Route>,
}

impl RouteTable {
    fn insert(&mut self, method: Method, pattern: &str) -> String {
        assert!(
            pattern.starts_with('/'),
            "path must begin with '/' in path '{pattern}'"
        );
        let mut segments = Vec::new();
        let mut axum_path = String::with_capacity(pattern.len() + 8);
        for segment in pattern[1..].split('/') {
            axum_path.push('/');
            if let Some(name) = segment.strip_prefix(':') {
                assert!(!name.is_empty(), "empty parameter name in path '{pattern}'");
                segments.push(Segment::Param);
                axum_path.push('{');
                axum_path.push_str(name);
                axum_path.push('}');
            } else {
                assert!(
                    !segment.contains(['*', '{', '}']),
                    "unsupported segment '{segment}' in path '{pattern}'"
                );
                segments.push(Segment::Static(segment.to_owned()));
                axum_path.push_str(segment);
            }
        }
        assert!(
            !self
                .routes
                .iter()
                .any(|route| route.method == method && route.segments == segments),
            "handlers are already registered for path '{pattern}'"
        );
        self.routes.push(Route {
            method,
            segments,
            pattern: pattern.into(),
        });
        axum_path
    }

    fn find(&self, method: &Method, path: &str) -> Option<Arc<str>> {
        let rest = path.strip_prefix('/')?;
        let path_segments: Vec<&str> = rest.split('/').collect();
        self.routes
            .iter()
            .filter(|route| route.method == method && route.matches(&path_segments))
            .max_by_key(|route| route.priority())
            .map(|route| Arc::clone(&route.pattern))
    }

    fn has_method(&self, method: &Method) -> bool {
        self.routes.iter().any(|route| route.method == method)
    }

    /// gin `tsr`: the path with its trailing slash toggled is a route.
    fn trailing_slash_match(&self, method: &Method, path: &str) -> bool {
        match path.strip_suffix('/') {
            Some(trimmed) if path.len() > 1 => self.find(method, trimmed).is_some(),
            _ => self.find(method, &format!("{path}/")).is_some(),
        }
    }
}

/// Route builder with gin path syntax and gin dispatch rules.
///
/// Per-route middleware (gin group or route handlers such as the support
/// bearer check or the OTP limiter) goes on the `MethodRouter` with
/// `route_layer`.
#[derive(Debug)]
pub struct GinRouter<S = ()> {
    router: Router<S>,
    table: RouteTable,
}

impl<S: Clone + Send + Sync + 'static> Default for GinRouter<S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S: Clone + Send + Sync + 'static> GinRouter<S> {
    #[must_use]
    pub fn new() -> Self {
        Self {
            router: Router::new(),
            table: RouteTable::default(),
        }
    }

    /// Registers `method_router` for `method` on `path` (gin syntax). Only
    /// `method` is dispatched to it, whatever else it serves.
    ///
    /// # Panics
    ///
    /// On a malformed path or a duplicate (method, path), as gin does.
    #[must_use]
    pub fn route(mut self, method: Method, path: &str, method_router: MethodRouter<S>) -> Self {
        let axum_path = self.table.insert(method, path);
        self.router = self.router.route(&axum_path, method_router);
        self
    }

    /// gin `GET`.
    #[must_use]
    pub fn get<H, T>(self, path: &str, handler: H) -> Self
    where
        H: Handler<T, S>,
        T: 'static,
    {
        self.route(
            Method::GET,
            path,
            on(axum::routing::MethodFilter::GET, handler),
        )
    }

    /// gin `POST`.
    #[must_use]
    pub fn post<H, T>(self, path: &str, handler: H) -> Self
    where
        H: Handler<T, S>,
        T: 'static,
    {
        self.route(
            Method::POST,
            path,
            on(axum::routing::MethodFilter::POST, handler),
        )
    }

    /// Provides the handler state, like `axum::Router::with_state`.
    #[must_use]
    pub fn with_state<S2>(self, state: S) -> GinRouter<S2> {
        GinRouter {
            router: self.router.with_state(state),
            table: self.table,
        }
    }
}

impl GinRouter<()> {
    /// Wraps the routes and the 404 chain in `layers`, adds gin's dispatch
    /// (redirects outside the middleware) and returns a plain axum router.
    pub fn into_router(self, layers: &GlobalLayers) -> Router {
        let dispatch = Dispatch {
            table: self.table,
            routes: layers.wrap(self.router.fallback(not_found)),
            not_found: layers.wrap(Router::new().fallback(not_found)),
        };
        Router::new()
            .fallback(dispatch_request)
            .with_state(Arc::new(dispatch))
    }
}

struct Dispatch {
    table: RouteTable,
    routes: Router,
    not_found: Router,
}

async fn dispatch_request(State(dispatch): State<Arc<Dispatch>>, mut request: Request) -> Response {
    let raw_path = request.uri().path();
    // Deviation: Go's server rejects an invalid escape with 400 before gin
    // sees the request; here the raw path is matched instead.
    let path = go_url::unescape_path(raw_path).unwrap_or_else(|_| raw_path.to_owned());
    let method = request.method().clone();

    if let Some(full_path) = dispatch.table.find(&method, &path) {
        request.extensions_mut().insert(FullPath(full_path));
        canonicalize_path(&mut request, &path);
        return call(dispatch.routes.clone(), request).await;
    }
    if method != Method::CONNECT
        && path != "/"
        && dispatch.table.has_method(&method)
        && dispatch.table.trailing_slash_match(&method, &path)
    {
        return trailing_slash_redirect(&request, &path);
    }
    call(dispatch.not_found.clone(), request).await
}

/// gin matches the decoded path (`/heal%74hz` is `/healthz`) while axum
/// matches the raw one, so a matched request is handed to axum with its path
/// re-escaped the way Go's `URL.EscapedPath` would (`%20` stays `%20`, so
/// `Path` extractors still decode parameters).
fn canonicalize_path(request: &mut Request, decoded_path: &str) {
    // Only an escaped request path can disagree with the decoded match.
    if !request.uri().path().contains('%') {
        return;
    }
    let escaped = go_url::escape_path(decoded_path);
    if escaped == request.uri().path() {
        return;
    }
    let path_and_query = match request.uri().query() {
        Some(query) => format!("{escaped}?{query}"),
        None => escaped,
    };
    let mut parts = request.uri().clone().into_parts();
    if let Ok(value) = path_and_query.parse() {
        parts.path_and_query = Some(value);
        if let Ok(uri) = axum::http::Uri::from_parts(parts) {
            *request.uri_mut() = uri;
        }
    }
}

async fn call(mut router: Router, request: Request) -> Response {
    // `Router` is always ready (axum documents `poll_ready` as always
    // `Ready`), so `call` can be used without `poll_ready`.
    match router.call(request).await {
        Ok(response) => response,
        Err(never) => match never {},
    }
}

/// gin `NoRoute` default: `404` `text/plain` `404 page not found`.
pub async fn not_found() -> Response {
    let mut response = Response::new(Body::from(NOT_FOUND_BODY));
    *response.status_mut() = StatusCode::NOT_FOUND;
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));
    response
}

/// gin `redirectTrailingSlash` (keep only `[A-Za-z0-9/-]` of the cleaned
/// prefix, collapse repeated `/`).
fn trailing_slash_target(path: &str, forwarded_prefix: &str) -> String {
    let mut p = path.to_owned();
    let prefix = go_url::path_clean(forwarded_prefix);
    if prefix != "." {
        let sanitized: String = prefix
            .chars()
            .filter(|&c| c.is_ascii_alphanumeric() || c == '/' || c == '-')
            .collect();
        let mut collapsed = String::with_capacity(sanitized.len());
        for c in sanitized.chars() {
            if !(c == '/' && collapsed.ends_with('/')) {
                collapsed.push(c);
            }
        }
        p = format!("{collapsed}/{path}");
    }
    if p.len() > 1 && p.ends_with('/') {
        p.pop();
        p
    } else {
        p + "/"
    }
}

/// The `Location` gin sends: Go `URL.String()` of the rewritten URL, then the
/// relative-path handling of `http.Redirect`.
fn redirect_location(new_path: &str, raw_query: Option<&str>) -> String {
    let escaped_path = go_url::escape_path(new_path);
    let mut url = String::with_capacity(escaped_path.len() + 16);
    // URL.String: a relative reference whose first segment holds a colon
    // gets a "./" prefix.
    let first_segment = escaped_path.split('/').next().unwrap_or_default();
    if first_segment.contains(':') {
        url.push_str("./");
    }
    url.push_str(&escaped_path);
    if let Some(query) = raw_query {
        url.push('?');
        url.push_str(query);
    }

    // http.Redirect: make a host-less URL absolute and clean it.
    let Ok(parsed) = go_url::parse(&url) else {
        return url;
    };
    if !parsed.scheme.is_empty() || !parsed.host.is_empty() {
        return url;
    }
    if !url.starts_with('/') {
        let old_path = if escaped_path.is_empty() {
            "/"
        } else {
            escaped_path.as_str()
        };
        url = format!("{}{url}", go_url::path_split(old_path).0);
    }
    let (path_part, query) = match url.find('?') {
        Some(i) => url.split_at(i),
        None => (url.as_str(), ""),
    };
    let mut cleaned = go_url::path_clean(path_part);
    if path_part.ends_with('/') && !cleaned.ends_with('/') {
        cleaned.push('/');
    }
    cleaned + query
}

/// Go `htmlEscape` (`http.Redirect` body).
fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&#34;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

fn trailing_slash_redirect(request: &Request, path: &str) -> Response {
    let forwarded_prefix = request
        .headers()
        .get("x-forwarded-prefix")
        .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned())
        .unwrap_or_default();
    let target = trailing_slash_target(path, &forwarded_prefix);
    // The request target is ASCII, so Go's `hexEscapeNonASCII` is a no-op.
    let location = redirect_location(&target, request.uri().query());

    let is_get = request.method() == Method::GET;
    let status = if is_get {
        StatusCode::MOVED_PERMANENTLY
    } else {
        StatusCode::TEMPORARY_REDIRECT
    };
    let body = if is_get {
        format!(
            "<a href=\"{}\">{}</a>.\n\n",
            html_escape(&location),
            status.canonical_reason().unwrap_or_default()
        )
    } else {
        String::new()
    };
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    if let Ok(value) = HeaderValue::from_str(&location) {
        response.headers_mut().insert(header::LOCATION, value);
    }
    if is_get || request.method() == Method::HEAD {
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/html; charset=utf-8"),
        );
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    fn location(path: &str, prefix: &str, query: Option<&str>) -> String {
        redirect_location(&trailing_slash_target(path, prefix), query)
    }

    #[test]
    fn redirect_locations() {
        assert_eq!(location("/healthz/", "", None), "/healthz");
        assert_eq!(location("/healthz", "", None), "/healthz/");
        assert_eq!(location("/healthz/", "", Some("a=1&b")), "/healthz?a=1&b");
        assert_eq!(location("/healthz/", "", Some("")), "/healthz?");
        assert_eq!(location("/healthz/", "/api", None), "/api/healthz");
        assert_eq!(location("/healthz/", "/api/", None), "/api/healthz");
        assert_eq!(location("/healthz/", "/a.b_c!/x", None), "/abc/x/healthz");
        assert_eq!(location("/healthz/", "api", None), "api/api/healthz");
        assert_eq!(location("/healthz/", "!!!", None), "//healthz");
        assert_eq!(location("/healthz/", "/../..", None), "/healthz");
        assert_eq!(location("/a b/", "", None), "/a%20b");
    }

    #[test]
    fn table_matching() {
        let mut table = RouteTable::default();
        assert_eq!(
            table.insert(Method::GET, "/v1/clients/:clientID/public-info"),
            "/v1/clients/{clientID}/public-info"
        );
        table.insert(Method::GET, "/v1/clients/static/public-info");
        table.insert(Method::POST, "/v1/oauth2/token");
        assert_eq!(
            table
                .find(&Method::GET, "/v1/clients/abc/public-info")
                .as_deref(),
            Some("/v1/clients/:clientID/public-info")
        );
        assert_eq!(
            table
                .find(&Method::GET, "/v1/clients/static/public-info")
                .as_deref(),
            Some("/v1/clients/static/public-info")
        );
        assert_eq!(table.find(&Method::GET, "/v1/clients//public-info"), None);
        assert_eq!(
            table.find(&Method::HEAD, "/v1/clients/abc/public-info"),
            None
        );
        assert!(table.trailing_slash_match(&Method::POST, "/v1/oauth2/token/"));
        assert!(!table.trailing_slash_match(&Method::GET, "/v1/oauth2/token/"));
        assert!(table.trailing_slash_match(&Method::GET, "/v1/clients/x/public-info/"));
    }

    #[test]
    #[should_panic(expected = "already registered")]
    fn duplicate_route_panics() {
        let mut table = RouteTable::default();
        table.insert(Method::GET, "/a/:x");
        table.insert(Method::GET, "/a/:y");
    }
}
