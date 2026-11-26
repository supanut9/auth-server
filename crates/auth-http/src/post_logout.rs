//! `router.go` `postLogoutRedirect` and `sameOriginURL`.

use auth_adapters::config::Config;

use crate::go_url;

/// The logout redirect target: `candidate` when it has the same scheme and
/// host (including any port; ASCII-case-insensitive; path ignored) as
/// `AUTH_UI_BASE_URL` or an entry of `POST_LOGOUT_REDIRECT_ALLOWLIST`,
/// otherwise `{AUTH_UI_BASE_URL without trailing /}/logout`. An empty
/// candidate also yields the default.
#[must_use]
pub fn post_logout_redirect(
    candidate: &str,
    auth_ui_base_url: &str,
    allowlist: &[String],
) -> String {
    let default_target = format!("{}/logout", auth_ui_base_url.trim_end_matches('/'));
    if candidate.is_empty() {
        return default_target;
    }
    if same_origin_url(candidate, auth_ui_base_url)
        || allowlist
            .iter()
            .any(|allowed| same_origin_url(candidate, allowed))
    {
        return candidate.to_owned();
    }
    default_target
}

/// [`post_logout_redirect`] with the configured base URL and allowlist.
#[must_use]
pub fn post_logout_redirect_for(config: &Config, candidate: &str) -> String {
    post_logout_redirect(
        candidate,
        &config.auth_ui_base_url,
        &config.post_logout_redirect_allowlist,
    )
}

/// Go `sameOriginURL`: both parse (Go `url.Parse`) with a scheme and a host,
/// and both match under `strings.EqualFold`.
#[must_use]
pub fn same_origin_url(candidate: &str, base: &str) -> bool {
    let (Ok(candidate), Ok(base)) = (go_url::parse(candidate), go_url::parse(base)) else {
        return false;
    };
    if candidate.scheme.is_empty()
        || candidate.host.is_empty()
        || base.scheme.is_empty()
        || base.host.is_empty()
    {
        return false;
    }
    equal_fold(&candidate.scheme, &base.scheme) && equal_fold(&candidate.host, &base.host)
}

/// Go `strings.EqualFold` (simple Unicode case folding), approximated by
/// comparing per-character lowercase mappings.
fn equal_fold(a: &str, b: &str) -> bool {
    a.chars()
        .flat_map(char::to_lowercase)
        .eq(b.chars().flat_map(char::to_lowercase))
}

#[cfg(test)]
mod tests {
    use super::*;

    const UI: &str = "https://auth-ui.example";

    // Port of router_security_test.go.

    #[test]
    fn accepts_same_origin() {
        let candidate = "https://auth-ui.example/logout/signed-out";
        assert_eq!(post_logout_redirect(candidate, UI, &[]), candidate);
    }

    #[test]
    fn rejects_cross_origin() {
        assert_eq!(
            post_logout_redirect("https://evil.example/logout", UI, &[]),
            "https://auth-ui.example/logout"
        );
    }

    #[test]
    fn accepts_allowlisted_origin() {
        let candidate = "https://community.example/logout";
        assert_eq!(
            post_logout_redirect(candidate, UI, &["https://community.example".to_owned()]),
            candidate
        );
    }

    // Beyond the Go tests.

    #[test]
    fn origin_rules() {
        let allow = ["https://community.example:8443/ignored/path".to_owned()];
        let ok =
            |candidate: &str| post_logout_redirect(candidate, "https://auth-ui.example/", &allow);
        let fallback = "https://auth-ui.example/logout";
        assert_eq!(ok(""), fallback);
        assert_eq!(
            ok("HTTPS://AUTH-UI.EXAMPLE/x?y#z"),
            "HTTPS://AUTH-UI.EXAMPLE/x?y#z"
        );
        assert_eq!(ok("https://auth-ui.example:443/x"), fallback);
        assert_eq!(ok("http://auth-ui.example/x"), fallback);
        assert_eq!(
            ok("https://community.example:8443/a"),
            "https://community.example:8443/a"
        );
        assert_eq!(ok("https://community.example/a"), fallback);
        assert_eq!(
            ok("https://user@auth-ui.example/x"),
            "https://user@auth-ui.example/x"
        );
        assert_eq!(ok("//auth-ui.example/x"), fallback);
        assert_eq!(ok("/logout"), fallback);
        assert_eq!(ok("https://auth-ui.example/%zz"), fallback);
        assert_eq!(ok("https://auth-ui.example:x/"), fallback);
        assert_eq!(ok("javascript:alert(1)"), fallback);
        // Also checked against Go 1.26 `url.Parse`.
        assert_eq!(ok("https://auth-ui.example#%zz"), fallback);
        assert_eq!(ok("https://a:1:2/"), fallback);
        assert_eq!(ok("https://us er@auth-ui.example/"), fallback);
        assert_eq!(ok("https://[::1]:80/"), fallback);
    }
}
