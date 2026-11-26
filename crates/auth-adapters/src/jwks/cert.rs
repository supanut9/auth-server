//! Minimal X.509 walker: finds `subjectPublicKeyInfo` in a DER certificate.
//!
//! Go accepts a certificate as `JWT_PUBLIC_KEY_PEM` (`x509.ParseCertificate`
//! fallback). Only the key is used, so this reads the TBSCertificate field
//! order without validating the rest of the certificate.

/// One DER TLV.
struct Tlv<'a> {
    tag: u8,
    content: &'a [u8],
    /// The whole encoding (tag, length and content).
    whole: &'a [u8],
    /// Input after this TLV.
    rest: &'a [u8],
}

fn read_tlv(input: &[u8]) -> Option<Tlv<'_>> {
    let (&tag, after_tag) = input.split_first()?;
    let (&first, after_len) = after_tag.split_first()?;
    let (len, header) = if first < 0x80 {
        (usize::from(first), 2)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 4 || after_len.len() < count {
            return None;
        }
        let len = after_len[..count]
            .iter()
            .fold(0_usize, |acc, &b| (acc << 8) | usize::from(b));
        (len, 2 + count)
    };
    let end = header.checked_add(len)?;
    if input.len() < end {
        return None;
    }
    Some(Tlv {
        tag,
        content: &input[header..end],
        whole: &input[..end],
        rest: &input[end..],
    })
}

const SEQUENCE: u8 = 0x30;
const INTEGER: u8 = 0x02;
const VERSION: u8 = 0xa0;

/// DER of the certificate's `SubjectPublicKeyInfo`, or `None` when `der` is
/// not shaped like a certificate.
pub(crate) fn subject_public_key_info(der: &[u8]) -> Option<&[u8]> {
    let certificate = read_tlv(der)?;
    if certificate.tag != SEQUENCE || !certificate.rest.is_empty() {
        return None;
    }
    let tbs = read_tlv(certificate.content)?;
    if tbs.tag != SEQUENCE {
        return None;
    }
    let mut rest = tbs.content;
    let first = read_tlv(rest)?;
    if first.tag == VERSION {
        rest = first.rest;
    }
    // serialNumber, signature, issuer, validity, subject.
    for expected in [INTEGER, SEQUENCE, SEQUENCE, SEQUENCE, SEQUENCE] {
        let field = read_tlv(rest)?;
        if field.tag != expected {
            return None;
        }
        rest = field.rest;
    }
    let spki = read_tlv(rest)?;
    (spki.tag == SEQUENCE).then_some(spki.whole)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_certificates() {
        assert_eq!(subject_public_key_info(b""), None);
        assert_eq!(subject_public_key_info(&[0x30, 0x00]), None);
        assert_eq!(subject_public_key_info(&[0x30, 0x05, 0x02]), None);
        assert_eq!(
            subject_public_key_info(&[0x30, 0x84, 0xff, 0xff, 0xff, 0xff]),
            None
        );
    }

    #[test]
    fn long_form_lengths() {
        let mut der = vec![0x04, 0x81, 0x80];
        der.extend([7_u8; 0x80]);
        let tlv = read_tlv(&der).expect("tlv");
        assert_eq!(
            (tlv.tag, tlv.content.len(), tlv.whole.len(), tlv.rest.len()),
            (0x04, 0x80, 0x83, 0)
        );
    }
}
