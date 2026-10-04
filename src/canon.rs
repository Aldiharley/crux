//! Canonical JSON + SHA-256, byte-identical to Python's
//! `json.dumps(obj, sort_keys=True, separators=(",", ":"))` (default `ensure_ascii=True`).
//!
//! The audit chain and finding hashes are defined over this encoding, so a log written
//! by the Python reference verifies under Rust and vice versa.

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fmt::Write;

/// Serialise `v` with sorted keys, compact separators, ASCII-only escaping and
/// Python's float repr.
pub fn to_canonical_json(v: &Value) -> String {
    let mut out = String::new();
    write_value(&mut out, v);
    out
}

/// Lowercase hex SHA-256 of the canonical encoding of `v`.
pub fn hash_value(v: &Value) -> String {
    sha256_hex(to_canonical_json(v).as_bytes())
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut s = String::with_capacity(64);
    for b in digest {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn write_value(out: &mut String, v: &Value) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => match n.as_f64() {
            Some(f) if n.is_f64() => out.push_str(&py_float_repr(f)),
            _ => out.push_str(&n.to_string()),
        },
        Value::String(s) => write_str(out, s),
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(out, x);
            }
            out.push(']');
        }
        Value::Object(m) => {
            // Sort explicitly: serde_json's Map is only sorted when the
            // `preserve_order` feature is off, and features unify across a build.
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_str(out, k);
                out.push(':');
                write_value(out, &m[k]);
            }
            out.push('}');
        }
    }
}

/// Python `ensure_ascii` string escaping: everything outside printable ASCII
/// (0x20..=0x7e) becomes `\uXXXX` (UTF-16, lowercase hex).
fn write_str(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            ' '..='~' => out.push(c),
            _ => {
                let mut buf = [0u16; 2];
                for unit in c.encode_utf16(&mut buf) {
                    let _ = write!(out, "\\u{unit:04x}");
                }
            }
        }
    }
    out.push('"');
}

/// Python's `repr(float)`: shortest round-trip digits; positional notation when the
/// decimal exponent is in [-4, 16), otherwise `d.ddde+XX`.
pub fn py_float_repr(f: f64) -> String {
    if f.is_nan() {
        return "NaN".into();
    }
    if f.is_infinite() {
        return if f > 0.0 { "Infinity" } else { "-Infinity" }.into();
    }
    let sci = format!("{f:e}"); // shortest digits, e.g. "1.2345e-1", "-5e-324"
    let (mantissa, exp) = sci.split_once('e').expect("{:e} always has an exponent");
    let exp: i32 = exp.parse().expect("exponent is an integer");
    if (-4..16).contains(&exp) {
        let s = format!("{f}");
        if s.contains('.') {
            s
        } else {
            format!("{s}.0")
        }
    } else {
        let sign = if exp < 0 { '-' } else { '+' };
        format!("{mantissa}e{sign}{:02}", exp.abs())
    }
}

/// Python's `round(x, 4)`: correctly rounded on the exact binary value.
pub fn round4(x: f64) -> f64 {
    format!("{x:.4}").parse().unwrap_or(x)
}

#[cfg(test)]
mod t {
    use super::*;
    use serde_json::json;

    #[test]
    fn float_repr_matches_python() {
        for (f, want) in [
            (1.0, "1.0"),
            (0.0, "0.0"),
            (-0.0, "-0.0"),
            (0.85, "0.85"),
            (0.0001, "0.0001"),
            (0.00001, "1e-05"),
            (1.5e-7, "1.5e-07"),
            (1e16, "1e+16"),
            (123456789012345.6, "123456789012345.6"),
            (0.1 + 0.2, "0.30000000000000004"),
        ] {
            assert_eq!(py_float_repr(f), want, "{f}");
        }
    }

    #[test]
    fn sorted_compact_ascii() {
        let v = json!({"b": 1, "a": [true, null, 0.5], "\u{e9}": "x\u{1f600}\u{7f}/\"\\\n"});
        assert_eq!(
            to_canonical_json(&v),
            r#"{"a":[true,null,0.5],"b":1,"BSu00e9":"xBSud83dBSude00BSu007f/BS"BSBSBSn"}"#
                .replace("BS", "\\")
        );
    }

    #[test]
    fn round4_is_exact_decimal_rounding() {
        assert_eq!(round4(0.85), 0.85);
        assert_eq!(round4(0.123449999), 0.1234);
        assert_eq!(round4(2.0 * (0.8f64 - 0.5).abs() + 0.05), 0.65);
    }
}
