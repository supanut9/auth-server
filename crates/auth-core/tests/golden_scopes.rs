//! `testdata/golden/scopes.json` against `auth_core::domain::Scopes`.
//!
//! `Scopes` models the sorted splitters only. `http_split_protocol_list`
//! (first-occurrence order, not sorted) and the client_credentials handler
//! rules belong to the HTTP lane and are not asserted here.

mod golden_support;

use auth_core::domain::Scopes;
use golden_support::{cases, load, s};
use serde_json::Value;

fn items(scopes: &Scopes) -> Vec<String> {
    scopes.iter().cloned().collect()
}

/// `null` and `[]` are both an empty Go slice for these purposes.
fn list(value: &Value) -> Vec<String> {
    match value {
        Value::Null => Vec::new(),
        Value::Array(items) => items
            .iter()
            .map(|item| item.as_str().expect("string").to_owned())
            .collect(),
        other => panic!("not a list: {other}"),
    }
}

fn check_split(section: &str, split: fn(&str) -> Scopes) -> usize {
    let doc = load("scopes.json");
    let cases = cases(&doc, section);
    for case in cases {
        let input = s(case, "input");
        let scopes = split(input);
        assert_eq!(items(&scopes), list(&case["output"]), "{section} {input:?}");
        assert_eq!(scopes.to_string(), s(case, "joined"), "{section} {input:?}");
    }
    cases.len()
}

#[test]
fn oauth_split_scopes() {
    assert_eq!(check_split("oauth_split_scopes", Scopes::parse), 10);
}

#[test]
fn token_split_scopes() {
    assert_eq!(
        check_split("token_split_scopes", Scopes::parse_whitespace),
        10
    );
}

#[test]
fn flow_split_scopes() {
    assert_eq!(
        check_split("flow_split_scopes", Scopes::parse_whitespace),
        10
    );
}

#[test]
fn token_normalize_scopes() {
    let doc = load("scopes.json");
    let cases = cases(&doc, "token_normalize_scopes");
    for case in cases {
        let scopes = Scopes::normalize(list(&case["input"]));
        assert_eq!(items(&scopes), list(&case["output"]), "{case}");
        assert_eq!(scopes.to_string(), s(case, "joined"), "{case}");
    }
    assert_eq!(cases.len(), 5);
}

#[test]
fn flow_union_scopes() {
    let doc = load("scopes.json");
    let cases = cases(&doc, "flow_union_scopes");
    for case in cases {
        // Go: normalizeScopes(base ++ extra); `Scopes` is already normalized,
        // so union the raw lists.
        let scopes = Scopes::normalize(list(&case["base"]).into_iter().chain(list(&case["extra"])));
        assert_eq!(items(&scopes), list(&case["output"]), "{case}");
        assert_eq!(scopes.to_string(), s(case, "joined"), "{case}");

        let unioned =
            Scopes::normalize(list(&case["base"])).union(&Scopes::normalize(list(&case["extra"])));
        assert_eq!(unioned, scopes, "{case}");
    }
    assert_eq!(cases.len(), 4);
}

#[test]
fn flow_scope_subset() {
    let doc = load("scopes.json");
    let cases = cases(&doc, "flow_scope_subset");
    for case in cases {
        let requested = Scopes::normalize(list(&case["requested"]));
        let granted = Scopes::normalize(list(&case["granted"]));
        assert_eq!(
            requested.is_subset_of(&granted),
            case["subset"].as_bool().expect("subset"),
            "{case}"
        );
    }
    assert_eq!(cases.len(), 6);
}
