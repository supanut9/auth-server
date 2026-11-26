//! Go `strings` helpers the identity rules depend on.

/// Go `strings.EqualFold`: equal under Unicode simple case folding, compared
/// character by character.
///
/// Two characters match when they are equal, when their single-character
/// lowercase forms are equal (`K`/`k`/Kelvin sign), or when their
/// single-character uppercase forms are equal (`s`/`ſ`, `σ`/`ς`). Dotless
/// `ı` is excluded from the uppercase rule because it has no simple case
/// folding, so Go does not match it with `I` or `i`.
#[must_use]
pub fn equal_fold(a: &str, b: &str) -> bool {
    let mut left = a.chars();
    let mut right = b.chars();
    loop {
        match (left.next(), right.next()) {
            (None, None) => return true,
            (Some(x), Some(y)) if chars_fold_equal(x, y) => {}
            _ => return false,
        }
    }
}

fn chars_fold_equal(a: char, b: char) -> bool {
    if a == b {
        return true;
    }
    if a.is_ascii() && b.is_ascii() {
        return a.eq_ignore_ascii_case(&b);
    }
    if let (Some(x), Some(y)) = (single(a.to_lowercase()), single(b.to_lowercase()))
        && x == y
    {
        return true;
    }
    if a == '\u{131}' || b == '\u{131}' {
        return false;
    }
    matches!(
        (single(a.to_uppercase()), single(b.to_uppercase())),
        (Some(x), Some(y)) if x == y
    )
}

fn single(mut chars: impl Iterator<Item = char>) -> Option<char> {
    let first = chars.next()?;
    chars.next().is_none().then_some(first)
}

/// Go `fallbackDisplayName`: `name` when it is not blank, else the part of
/// `email` before the first `@` (when that part is non-empty), else `email`.
#[must_use]
pub fn fallback_display_name(name: &str, email: &str) -> String {
    if !name.trim().is_empty() {
        return name.to_owned();
    }
    match email.find('@') {
        Some(at) if at > 0 => email[..at].to_owned(),
        _ => email.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equal_fold_matches_go() {
        let equal = [
            ("", ""),
            ("User@Example.COM", "user@example.com"),
            ("\u{212a}", "k"),
            ("\u{212a}", "K"),
            ("\u{17f}", "S"),
            ("σ", "ς"),
            ("Σ", "ς"),
            ("ÀÉ@x", "àé@X"),
        ];
        for (a, b) in equal {
            assert!(equal_fold(a, b), "{a:?} {b:?}");
        }
        let different = [
            ("a", ""),
            ("ab", "a"),
            ("ß", "SS"),
            ("\u{131}", "I"),
            ("\u{131}", "i"),
            ("\u{130}", "i"),
            ("a@x", "b@x"),
        ];
        for (a, b) in different {
            assert!(!equal_fold(a, b), "{a:?} {b:?}");
        }
    }

    #[test]
    fn fallback_display_name_matches_go() {
        assert_eq!(fallback_display_name("Alice", "a@x"), "Alice");
        assert_eq!(fallback_display_name(" Al ", "a@x"), " Al ");
        assert_eq!(fallback_display_name("  ", "bob@x"), "bob");
        assert_eq!(fallback_display_name("", "@x"), "@x");
        assert_eq!(fallback_display_name("", "nobody"), "nobody");
        assert_eq!(fallback_display_name("", "a@b@c"), "a");
    }
}
