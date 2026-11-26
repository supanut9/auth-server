//! `testdata/golden/masking.json`: Go `maskEmail`, byte-exact, including
//! the mid-rune cut of multi-byte local parts.

mod golden_support;

use std::collections::BTreeSet;

use auth_core::identity::{mask_email, mask_email_bytes, mask_email_json};
use golden_support::{cases, load, s, sections};

#[test]
fn every_section_is_covered() {
    let want: BTreeSet<String> = ["mask_email".to_owned()].into_iter().collect();
    assert_eq!(sections(&load("masking.json")), want);
}

#[test]
fn mask_email_matches_go() {
    let doc = load("masking.json");
    let cases = cases(&doc, "mask_email");
    assert_eq!(cases.len(), 13, "every recorded case is checked");
    for case in cases {
        let input_bytes = hex::decode(s(case, "input_hex")).expect("input_hex");
        let input = std::str::from_utf8(&input_bytes).expect("inputs are valid UTF-8");
        assert_eq!(input, s(case, "input"));

        let bytes = mask_email_bytes(input);
        assert_eq!(
            hex::encode(&bytes),
            s(case, "output_hex"),
            "{input:?} bytes"
        );
        assert_eq!(
            std::str::from_utf8(&bytes).is_ok(),
            case["output_valid_utf8"]
                .as_bool()
                .expect("output_valid_utf8"),
            "{input:?} validity"
        );

        // `output` is the lossy decode of the bytes (U+FFFD per bad byte).
        let decoded = mask_email(input);
        assert_eq!(decoded, s(case, "output"), "{input:?} decoded");
        assert_eq!(
            decoded,
            String::from_utf8_lossy(&bytes),
            "{input:?} lossy decode agrees"
        );

        // `json_rendered` is the exact token gin writes.
        let json = mask_email_json(input);
        assert_eq!(json, s(case, "json_rendered"), "{input:?} json");
        let parsed: String = serde_json::from_str(&json).expect("valid JSON string");
        assert_eq!(parsed, decoded, "{input:?} json value");
    }
}
