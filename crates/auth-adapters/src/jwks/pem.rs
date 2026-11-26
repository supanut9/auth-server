//! Port of Go `encoding/pem.Decode` (first block only).
//!
//! Go skips any text before the first `-----BEGIN ` line, tolerates headers,
//! strips spaces and tabs from the body and lets the base64 decoder skip
//! `\r`/`\n`. Malformed candidates are skipped and the search continues. The
//! block type is not checked by the key loaders, matching Go.

use base64::Engine as _;
use base64::alphabet::STANDARD;
use base64::engine::{GeneralPurpose, GeneralPurposeConfig};

/// Go's `base64.StdEncoding` is not strict about trailing bits.
const STD_LENIENT: GeneralPurpose = GeneralPurpose::new(
    &STANDARD,
    GeneralPurposeConfig::new().with_decode_allow_trailing_bits(true),
);

const PEM_START: &[u8] = b"\n-----BEGIN ";
const PEM_END: &[u8] = b"\n-----END ";
const PEM_END_OF_LINE: &[u8] = b"-----";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Block {
    pub(crate) kind: String,
    pub(crate) bytes: Vec<u8>,
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn trim_right_space_tab(mut line: &[u8]) -> &[u8] {
    while let [rest @ .., b' ' | b'\t'] = line {
        line = rest;
    }
    line
}

/// Go `getLine`: the line without its `\n` / `\r\n` and trailing spaces/tabs.
fn get_line(data: &[u8]) -> (&[u8], &[u8]) {
    match data.iter().position(|&b| b == b'\n') {
        None => (trim_right_space_tab(data), &data[data.len()..]),
        Some(i) => {
            let end = if i > 0 && data[i - 1] == b'\r' {
                i - 1
            } else {
                i
            };
            (trim_right_space_tab(&data[..end]), &data[i + 1..])
        }
    }
}

fn decode_body(body: &[u8]) -> Option<Vec<u8>> {
    let cleaned: Vec<u8> = body
        .iter()
        .copied()
        .filter(|b| !matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
        .collect();
    STD_LENIENT.decode(cleaned).ok()
}

/// Go `pem.Decode(data)`, returning only the block.
pub(crate) fn decode(data: &[u8]) -> Option<Block> {
    let mut rest = data;
    loop {
        if let Some(after) = rest.strip_prefix(&PEM_START[1..]) {
            rest = after;
        } else {
            let i = find(rest, PEM_START)?;
            rest = &rest[i + PEM_START.len()..];
        }

        let (type_line, after_type) = get_line(rest);
        rest = after_type;
        let Some(kind) = type_line.strip_suffix(PEM_END_OF_LINE) else {
            continue;
        };

        let mut headers = 0_usize;
        loop {
            if rest.is_empty() {
                return None;
            }
            let (line, next) = get_line(rest);
            if !line.contains(&b':') {
                break;
            }
            headers += 1;
            rest = next;
        }

        let (end_index, end_trailer_index) = if headers == 0 && rest.starts_with(&PEM_END[1..]) {
            (0, PEM_END.len() - 1)
        } else {
            match find(rest, PEM_END) {
                Some(i) => (i, i + PEM_END.len()),
                None => continue,
            }
        };

        let end_trailer = &rest[end_trailer_index..];
        let trailer_len = kind.len() + PEM_END_OF_LINE.len();
        if end_trailer.len() < trailer_len {
            continue;
        }
        let (end_trailer, rest_of_end_line) = end_trailer.split_at(trailer_len);
        if !end_trailer.starts_with(kind) || !end_trailer.ends_with(PEM_END_OF_LINE) {
            continue;
        }
        if !get_line(rest_of_end_line).0.is_empty() {
            continue;
        }
        let Some(bytes) = decode_body(&rest[..end_index]) else {
            continue;
        };
        return Some(Block {
            kind: String::from_utf8_lossy(kind).into_owned(),
            bytes,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_like_go() {
        let block = decode(b"junk\n-----BEGIN X-----\nQUJD\n-----END X-----\n").expect("block");
        assert_eq!(
            block,
            Block {
                kind: "X".into(),
                bytes: b"ABC".to_vec()
            }
        );

        // Headers, CRLF and indentation.
        let block = decode(b"-----BEGIN X-----\r\nProc-Type: 4\r\n\r\n QU\tJD \r\n-----END X-----")
            .expect("block");
        assert_eq!(block.bytes, b"ABC");

        // Empty body.
        assert_eq!(
            decode(b"-----BEGIN X-----\n-----END X-----")
                .expect("block")
                .bytes,
            b""
        );

        // A broken first candidate is skipped; the second block is found.
        let block = decode(
            b"-----BEGIN A-----\n!!!!\n-----END A-----\n-----BEGIN B-----\nQUJD\n-----END B-----\n",
        )
        .expect("block");
        assert_eq!(block.kind, "B");

        for bad in [
            &b"not a pem"[..],
            b"-----BEGIN X-----\nQUJD\n-----END Y-----\n",
            b"-----BEGIN X-----\\nQUJD\\n-----END X-----",
            b"-----BEGIN X-----\nQUJD\n-----END X----- trailing\n",
            b"-----BEGIN X-----\nQUJ\n-----END X-----\n",
            b"-----BEGIN X-----",
        ] {
            assert_eq!(decode(bad), None, "{:?}", String::from_utf8_lossy(bad));
        }
    }
}
