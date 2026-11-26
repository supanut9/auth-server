//! OAuth scope sets.

use std::collections::BTreeSet;
use std::fmt;

/// A deduplicated, byte-order sorted scope set (Go `sort.Strings` order).
///
/// Renders space-joined. Entities keep raw scope strings as stored; this type
/// is what services compute with.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct Scopes(Vec<String>);

impl Scopes {
    /// Parses a request or client-registry scope string like Go
    /// `oauth.splitScopes`: splits on space, comma, `\n` and `\t`, trims
    /// Unicode whitespace from each item, drops empties, dedupes and sorts.
    #[must_use]
    pub fn parse(raw: &str) -> Self {
        Self::normalize(raw.split([' ', ',', '\n', '\t']))
    }

    /// Parses a stored scope string like the token/flow services' Go
    /// `splitScopes`: splits on any Unicode whitespace (`strings.Fields`) only.
    /// Commas are not separators here.
    #[must_use]
    pub fn parse_whitespace(raw: &str) -> Self {
        Self::normalize(raw.split_whitespace())
    }

    /// Go `normalizeScopes`: trim each item, drop empties, dedupe, sort.
    pub fn normalize<I, S>(items: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let set: BTreeSet<String> = items
            .into_iter()
            .filter_map(|item| {
                let trimmed = item.as_ref().trim();
                (!trimmed.is_empty()).then(|| trimmed.to_owned())
            })
            .collect();
        Self(set.into_iter().collect())
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn iter(&self) -> std::slice::Iter<'_, String> {
        self.0.iter()
    }

    #[must_use]
    pub fn as_slice(&self) -> &[String] {
        &self.0
    }

    #[must_use]
    pub fn into_vec(self) -> Vec<String> {
        self.0
    }

    #[must_use]
    pub fn contains(&self, scope: &str) -> bool {
        self.0
            .binary_search_by(|item| item.as_str().cmp(scope))
            .is_ok()
    }

    /// True when every scope in `self` is in `other` (an empty set is a subset).
    #[must_use]
    pub fn is_subset_of(&self, other: &Self) -> bool {
        self.0.iter().all(|scope| other.contains(scope))
    }

    #[must_use]
    pub fn union(&self, other: &Self) -> Self {
        Self::normalize(self.0.iter().chain(other.0.iter()))
    }
}

impl fmt::Display for Scopes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut items = self.0.iter();
        if let Some(first) = items.next() {
            f.write_str(first)?;
            for item in items {
                f.write_str(" ")?;
                f.write_str(item)?;
            }
        }
        Ok(())
    }
}

impl<S: AsRef<str>> FromIterator<S> for Scopes {
    fn from_iter<I: IntoIterator<Item = S>>(iter: I) -> Self {
        Self::normalize(iter)
    }
}

impl<'a> IntoIterator for &'a Scopes {
    type Item = &'a String;
    type IntoIter = std::slice::Iter<'a, String>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl IntoIterator for Scopes {
    type Item = String;
    type IntoIter = std::vec::IntoIter<String>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

#[cfg(test)]
mod tests {
    use super::Scopes;

    fn items(scopes: &Scopes) -> Vec<&str> {
        scopes.iter().map(String::as_str).collect()
    }

    #[test]
    fn parse_splits_dedupes_and_sorts() {
        let cases: &[(&str, &[&str])] = &[
            ("", &[]),
            ("   ", &[]),
            (" , ,\n\t", &[]),
            ("openid", &["openid"]),
            ("profile openid email", &["email", "openid", "profile"]),
            ("openid,profile", &["openid", "profile"]),
            ("openid\nprofile\temail", &["email", "openid", "profile"]),
            ("openid  openid profile", &["openid", "profile"]),
            ("b a B A", &["A", "B", "a", "b"]),
            ("offline_access openid", &["offline_access", "openid"]),
            // `\r` is not a separator; TrimSpace only strips item ends.
            ("openid\r profile", &["openid", "profile"]),
            ("openid\rprofile", &["openid\rprofile"]),
        ];
        for (raw, want) in cases {
            assert_eq!(items(&Scopes::parse(raw)), *want, "input {raw:?}");
        }
    }

    #[test]
    fn parse_whitespace_ignores_commas() {
        assert_eq!(
            items(&Scopes::parse_whitespace("openid,profile email")),
            ["email", "openid,profile"]
        );
        assert_eq!(
            items(&Scopes::parse_whitespace(" openid\r\nprofile\u{a0}email ")),
            ["email", "openid", "profile"]
        );
    }

    #[test]
    fn display_is_space_joined() {
        assert_eq!(
            Scopes::parse("profile, openid").to_string(),
            "openid profile"
        );
        assert_eq!(Scopes::default().to_string(), "");
    }

    #[test]
    fn subset_contains_and_union() {
        let allowed = Scopes::parse("openid profile email");
        assert!(Scopes::parse("email openid").is_subset_of(&allowed));
        assert!(Scopes::default().is_subset_of(&allowed));
        assert!(!Scopes::parse("openid admin").is_subset_of(&allowed));
        assert!(allowed.contains("profile"));
        assert!(!allowed.contains("prof"));

        let union = Scopes::parse("openid").union(&Scopes::parse("email openid"));
        assert_eq!(items(&union), ["email", "openid"]);
    }

    #[test]
    fn normalize_trims_items() {
        let scopes = Scopes::normalize([" profile ", "", "openid", "profile"]);
        assert_eq!(items(&scopes), ["openid", "profile"]);
        let collected: Scopes = ["b", "a"].into_iter().collect();
        assert_eq!(collected.into_vec(), ["a", "b"]);
    }
}
