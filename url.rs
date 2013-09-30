//! URL parsing and other utilities
//!
//! This module aims to be compliant with http://url.spec.whatwg.org/ rather
//! than RFC 3986. Where there are differences, they will be documented.
//!
//! The main goal of this module is correctness and flexibility. Performance will be pursued as a
//! secondary goal.

extern mod extra;

use std::vec;
use std::rt::io::net::ip::{IpAddr};
use std::ascii::{OwnedStrAsciiExt, AsciiCast};

use extra::hex::{FromHex, ToHex};

/// The possible errors when percent decoding a string
#[deriving(Eq, TotalEq, Ord, TotalOrd, Clone)]
pub enum PercentDecodeError {
    /// The string is not ASCII. The uint is the index where the first non-ASCII byte was found.
    NotAscii(uint),
    /// Decoding the string created invalid UTF-8.
    // This doesn't return the index to the percent sign that caused invalid utf8 because that
    // computation is fairly expensive.
    InvalidUtf8,
}

// The ASCII digits are code points in the range U+0030 to U+0039.
fn is_digit(c: u8) -> bool {
    c >= 0x30 && c <= 0x39
}

// The ASCII hex digits are ASCII digits or are code points in the range U+0041 to U+0046 or in the
// range U+0061 to U+0066.
fn is_hex(c: u8) -> bool {
    is_digit(c) || (c >= 0x41 && c <= 0x46) || (c >= 0x61 && c <= 0x66)
}

/// Percent decode a string.
///
/// Returns None if `inp` is not ASCII or if percent decoding it creates
/// invalid UTF-8.
pub fn percent_decode(string: &str) -> Result<~str, PercentDecodeError> {
    let mut num_percents = 0;
    for b in string.byte_iter() {
        if b >= 0x7F {
            return Err(NotAscii(string.byte_iter().position(|x| x == b).unwrap()));
        } else if b == '%' as u8 {
            num_percents += 1;
        }
    }
    // 1. Let p[ointer] be a pointer into string, initially zero (pointing to the first code point).
    let mut p = 0;
    // 2. Let bytes be an empty byte sequence.
    // We subtract num_percents*2 because %XX, 3 bytes, gets collapsed into 1
    let mut bytes = vec::with_capacity(string.len() - (num_percents * 2));
    // 3. While c is not the EOF code point, run these substeps:
    while p < string.len() {
        let c = string[p];
        // 1. While c is not "%" or the EOF code point, append to bytes a byte whose value is c's
        //    code point and increase pointer by one.
        if c != '%' as u8 {
            bytes.push(c);
            p += 1;
            loop;
        }
        // 2. If c is "%" and remaining does not start with two ASCII hex digits, append to
        //    bytes a byte whose value is c's code point, increase pointer by one.
        if string.slice_from(p).len() < 3 || !string.slice(p + 1, p + 3).byte_iter().all(is_hex) {
            bytes.push(c);
            p += 1;
            loop;
        }
        // 3. Otherwise, while c is "%" and remaining starts with two ASCII hex digits, append to
        //    bytes a byte whose value is remaining's two leading code points, interpreted as
        //    hexadecimal number, and increase pointer by three.
        // If we get here, we know the above condition is true
        bytes.push(string.slice(p+1, p+3).from_hex().unwrap()[0]);
        p += 3;
    }

    if std::str::is_utf8(bytes) {
        Ok(unsafe { std::str::raw::from_utf8_owned(bytes) })
    } else {
        Err(InvalidUtf8)
    }
}

/// The simple encode set are all code points less than U+0020 (i.e. excluding U+0020) and all code
/// points greater than U+007E.
pub fn simple_enc(c: char) -> bool {
    let x: u32 = unsafe { std::cast::transmute(c) };
    x < 0x20 || x > 0x7E
}

/// The default encode set is the simple encode set and code points U+0020, '"', "#", "<", ">", "?",
/// and "`".
pub fn default_enc(c: char) -> bool {
    static chars: &'static [char] = &[' ', '"', '<', '>', '?', '`'];
    simple_enc(c) || chars.iter().any(|&d| d == c)
}

/// The password encode set is the default encode set and code points "/", "@", and "\".
pub fn password_enc(c: char) -> bool {
    static chars: &'static [char] = &['/', '@', '\\'];
    default_enc(c) || chars.iter().any(|&d| d == c)
}

/// The username encode set is the password encode set and code point ":".
pub fn username_enc(c: char) -> bool {
    password_enc(c) || c == ':'
}

/// Percent encode a string, using a callback to decide which characters to encode.
/// Usually you want to use one of the above functions (default_enc etc).
pub fn percent_encode(s: &str, f: &fn(char) -> bool) -> ~str {
    // FIXME: this is quite slow and allocationy
    let mut v = vec::with_capacity(s.len()); // allocation

    // To utf-8 percent encode a code point, using an encode set, run these steps:
    for c in s.iter() {
        // If code point is not in encode set, return code point.
        if !f(c) {
            v.push(c);
        } else {
            // Let bytes be the result of running utf-8 encode on code point.
            let st = c.to_str(); // allocation
            // Percent encode each byte in bytes, and then return them concatenated, in the same order.
            for b in st.byte_iter() {
                v.push('%');
                let hex = (&[b]).to_hex().into_ascii_upper(); // allocation
                v.extend(&mut hex.iter())
            }
        }
    }

    std::str::from_chars(v) // allocation
}

pub enum Host {
    Domain(~[~str]),
    Ipv6Addr(IpAddr)
}

pub fn parse_host(input: &str) -> Option<Host> {
    if input.len() == 0 { return None; }
    if input[0] == ('[' as u8) {
        if input[input.len()-1] != (']' as u8) {
            return None;
        } else {
            return Some(Ipv6Addr(from_str(input.slice(1, input.len()-1)).unwrap()));
        }
    }

    if !input.is_ascii() {
        return None; // TODO: IDNA ToASCII here
    }

    // TODO: there are more domain label seps than .
    Some(Domain(input.split_iter('.').map(|x| x.to_owned()).to_owned_vec()))
}

impl ToStr for Host {
    fn to_str(&self) -> ~str {
        match self {
            &Domain(ref l) => l.connect("."),
            &Ipv6Addr(ref a) => a.to_str()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use extra::test::BenchHarness;

    #[test]
    fn test_percent_decode() {
        assert!(percent_decode("agbagahkja159saASG12!@#6") == Ok(~"agbagahkja159saASG12!@#6"));
        assert!(percent_decode("") == Ok(~""));
        assert!(percent_decode(" %20%20 ") == Ok(~"    "));
        assert!(percent_decode("☃") == Err(NotAscii(0)));
        assert!(percent_decode("%80") == Err(InvalidUtf8));
    }

    #[bench]
    fn bench_percent_decode_invalid_utf8_escape(bh: &mut BenchHarness) {
        do bh.iter {
            percent_decode("%80");
        }
    }

    #[bench]
    fn bench_percent_decode_not_ascii(bh: &mut BenchHarness) {
        do bh.iter {
            percent_decode("☃");
        }
    }

    #[bench]
    fn percent_decode_normal(bh: &mut BenchHarness) {
        do bh.iter {
            percent_decode("  %20 %35 %02 ");
        }
    }

    #[test]
    fn test_percent_encode() {
        use pe = percent_encode;
        assert_eq!(pe("Sinéad O’Connor", simple_enc), ~"Sin%C3%A9ad O%E2%80%99Connor")
        assert_eq!(pe("Sinéad O’Connor", default_enc), ~"Sin%C3%A9ad%20O%E2%80%99Connor")
        assert_eq!(pe("<?```> ", default_enc), ~"%3C%3F%60%60%60%3E%20");
    }

    #[bench]
    fn percent_encode_normal(bh: &mut BenchHarness) {
        do bh.iter {
            percent_encode("Sinéad O’Connor", default_enc);
        }
    }

    #[test]
    fn smoke_test_parse_host() {
        let hosts = ~[
            ~"[2607:f0d0:1002:51::4]",
            ~"a.b.c",
            ~"a."
        ];
        for host in hosts.iter() {
            parse_host(host.as_slice()).unwrap();
        }
    }
}
