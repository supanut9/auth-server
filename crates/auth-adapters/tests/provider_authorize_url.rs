//! Provider authorization URLs against `testdata/golden/redirects.json`.

use std::path::PathBuf;

use auth_adapters::provider::provider_authorization_url;
use serde_json::Value;

fn golden(file: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/golden")
        .join(file);
    let bytes = std::fs::read(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    serde_json::from_slice(&bytes).expect("golden json")
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key]
        .as_str()
        .unwrap_or_else(|| panic!("missing string {key}"))
}

#[test]
fn provider_authorization_urls_match_go() {
    let section = &golden("redirects.json")["provider_authorization_url"];
    let config = &section["config"];
    let cases = section["cases"].as_array().expect("cases");
    assert!(!cases.is_empty());
    for case in cases {
        let provider = text(case, "provider");
        let (client_id, redirect_uri) = match provider {
            "google" => (
                text(config, "google_client_id"),
                text(config, "google_redirect_url"),
            ),
            "github" => (
                text(config, "github_client_id"),
                text(config, "github_redirect_url"),
            ),
            _ => ("", ""),
        };
        let url =
            provider_authorization_url(provider, client_id, redirect_uri, text(case, "state"));
        assert_eq!(url, text(case, "url"), "provider {provider}");
    }
}
