//! Just enough DER reading to find a certificate's basic constraints. Every
//! read is bounds-checked; anything unexpected gives `None`.

const SEQUENCE: u8 = 0x30;
const BOOLEAN: u8 = 0x01;
const OID: u8 = 0x06;
const OCTET_STRING: u8 = 0x04;
const EXTENSIONS: u8 = 0xa3; // [3] EXPLICIT, constructed
/// 2.5.29.19, id-ce-basicConstraints.
const BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];

/// One tag-length-value element and the bytes after it.
fn element(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = input.split_first()?;
    if tag & 0x1f == 0x1f {
        return None; // multi-byte tags do not occur in the fields read here
    }
    let (&first, mut rest) = rest.split_first()?;
    let length = if first < 0x80 {
        usize::from(first)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 4 || rest.len() < count {
            return None;
        }
        let (bytes, after) = rest.split_at(count);
        rest = after;
        bytes
            .iter()
            .fold(0usize, |acc, &b| (acc << 8) | usize::from(b))
    };
    if rest.len() < length {
        return None;
    }
    let (value, after) = rest.split_at(length);
    Some((tag, value, after))
}

fn expect(input: &[u8], want: u8) -> Option<(&[u8], &[u8])> {
    let (tag, value, rest) = element(input)?;
    (tag == want).then_some((value, rest))
}

/// `Some(true)` when the certificate has basic constraints with `cA` set,
/// `Some(false)` when it does not, `None` when the DER cannot be read.
pub fn basic_constraints_ca(certificate: &[u8]) -> Option<bool> {
    let (cert, _) = expect(certificate, SEQUENCE)?;
    let (mut tbs, _) = expect(cert, SEQUENCE)?;
    while !tbs.is_empty() {
        let (tag, value, rest) = element(tbs)?;
        tbs = rest;
        if tag == EXTENSIONS {
            let (mut extensions, _) = expect(value, SEQUENCE)?;
            while !extensions.is_empty() {
                let (extension, rest) = expect(extensions, SEQUENCE)?;
                extensions = rest;
                if let Some(ca) = read_extension(extension)? {
                    return Some(ca);
                }
            }
            return Some(false);
        }
    }
    Some(false)
}

/// `Ok`-style result: outer `None` is a read error, inner `None` means
/// "not basic constraints".
fn read_extension(extension: &[u8]) -> Option<Option<bool>> {
    let (oid, mut rest) = expect(extension, OID)?;
    if oid != BASIC_CONSTRAINTS {
        return Some(None);
    }
    if let Some((BOOLEAN, _, after)) = element(rest) {
        rest = after; // the "critical" flag
    }
    let (octets, _) = expect(rest, OCTET_STRING)?;
    let (constraints, _) = expect(octets, SEQUENCE)?;
    match element(constraints) {
        Some((BOOLEAN, value, _)) => Some(Some(value.first().is_some_and(|&b| b != 0))),
        _ => Some(Some(false)),
    }
}
