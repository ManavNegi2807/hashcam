//! Canonical JSON for `abb/1`: RFC 8785 serialization and a strict parser.
//!
//! This crate owns the canonical bytes. Nothing else in the workspace may
//! serialize protocol JSON, and no third-party JSON crate is used, so the byte
//! sequence that gets hashed and signed has exactly one implementation
//! (`AGENTS.md` 3.10, `PROTOCOL.md` section 3).
//!
//! Rules enforced here, all from `PROTOCOL.md` section 3:
//!
//! * numbers are integers in `[-(2^53-1), 2^53-1]`; floats, exponents,
//!   fractions, `-0`, leading zeros, `NaN` and `Infinity` are rejected;
//!   nothing hashed may contain a float;
//! * object keys are sorted by **UTF-16 code unit**, which differs from code
//!   point order above U+FFFF;
//! * duplicate object keys, lone surrogates and invalid UTF-8 are rejected;
//! * optional fields are omitted, never `null` (a caller concern, not checked
//!   here);
//! * the protocol limits are 65,536 canonical bytes, depth 16 and 16,384 bytes
//!   per string.

#![forbid(unsafe_code)]

pub mod b64;

use std::fmt;

use sha2::{Digest, Sha256};

/// Stable rejection codes, as listed in `PROTOCOL.md` section 17.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// Fractional or exponent number form, or a float value.
    FloatNotAllowed,
    /// `NaN`, `Infinity` or `-Infinity`.
    NanOrInfinity,
    /// The token `-0`.
    MinusZero,
    /// A number with a leading zero, for example `01`.
    LeadingZero,
    /// Any other non-canonical number token, for example `+1`.
    NumberFormInvalid,
    /// Integer outside `[-(2^53-1), 2^53-1]`.
    IntOutOfRange,
    /// Repeated object key.
    DuplicateKey,
    /// Unpaired surrogate in a string or key.
    LoneSurrogate,
    /// Input bytes that are not valid UTF-8.
    InvalidUtf8,
    /// A single string over the byte limit.
    StringTooLong,
    /// The canonical form is over the byte limit.
    SizeExceeded,
    /// Nesting deeper than the limit.
    DepthExceeded,
    /// More than one JSON document in the input.
    TrailingData,
    /// Not JSON.
    SyntaxError,
}

impl Reason {
    /// The wire form of the code, as vectors and error payloads spell it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FloatNotAllowed => "FLOAT_NOT_ALLOWED",
            Self::NanOrInfinity => "NAN_OR_INFINITY",
            Self::MinusZero => "MINUS_ZERO",
            Self::LeadingZero => "LEADING_ZERO",
            Self::NumberFormInvalid => "NUMBER_FORM_INVALID",
            Self::IntOutOfRange => "INT_OUT_OF_RANGE",
            Self::DuplicateKey => "DUPLICATE_KEY",
            Self::LoneSurrogate => "LONE_SURROGATE",
            Self::InvalidUtf8 => "INVALID_UTF8",
            Self::StringTooLong => "STRING_TOO_LONG",
            Self::SizeExceeded => "SIZE_EXCEEDED",
            Self::DepthExceeded => "DEPTH_EXCEEDED",
            Self::TrailingData => "TRAILING_DATA",
            Self::SyntaxError => "SYNTAX_ERROR",
        }
    }
}

/// A rejection: a stable [`Reason`] plus context that is safe to log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalError {
    /// The stable code.
    pub reason: Reason,
    /// Short context. Never contains secrets; may name a key or a token.
    pub detail: String,
}

impl CanonicalError {
    fn new(reason: Reason, detail: impl Into<String>) -> Self {
        Self {
            reason,
            detail: detail.into(),
        }
    }
}

impl fmt::Display for CanonicalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.detail.is_empty() {
            write!(f, "{}", self.reason.as_str())
        } else {
            write!(f, "{}: {}", self.reason.as_str(), self.detail)
        }
    }
}

impl std::error::Error for CanonicalError {}

/// Result alias for this crate.
pub type Result<T> = std::result::Result<T, CanonicalError>;

/// Size, depth and string limits.
///
/// [`Limits::protocol`] is what every protocol document is parsed and
/// serialized under. [`Limits::relaxed`] exists only for tooling that reads
/// repository files such as the vector sets, which are larger than a single
/// protocol document is allowed to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Maximum canonical size in bytes.
    pub max_bytes: usize,
    /// Maximum nesting depth; the outermost container is depth 1.
    pub max_depth: usize,
    /// Maximum length of one string in UTF-8 bytes.
    pub max_string_bytes: usize,
}

impl Limits {
    /// The limits of `PROTOCOL.md` section 3.3 (D-06).
    #[must_use]
    pub const fn protocol() -> Self {
        Self {
            max_bytes: 65_536,
            max_depth: 16,
            max_string_bytes: 16_384,
        }
    }

    /// Tooling limits for reading repository files. Not for protocol documents.
    #[must_use]
    pub const fn relaxed() -> Self {
        Self {
            max_bytes: 64 << 20,
            max_depth: 64,
            max_string_bytes: 1 << 20,
        }
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self::protocol()
    }
}

/// A JSON value restricted to what the protocol allows.
///
/// Objects keep their parse order so a parsed document can be compared with the
/// bytes it came from; [`to_canonical`] sorts on output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// `null`, allowed only where a field says so.
    Null,
    /// `true` or `false`.
    Bool(bool),
    /// An integer in the protocol range.
    Int(i64),
    /// A string.
    Str(String),
    /// An array; order is significant and preserved.
    Array(Vec<Value>),
    /// An object, in parse order.
    Object(Vec<(String, Value)>),
}

impl Value {
    /// Look up a member of an object, or `None` for any other value.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Self::Object(entries) => entries.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// The string inside a [`Value::Str`].
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Str(s) => Some(s),
            _ => None,
        }
    }

    /// The integer inside a [`Value::Int`].
    #[must_use]
    pub const fn as_int(&self) -> Option<i64> {
        match self {
            Self::Int(i) => Some(*i),
            _ => None,
        }
    }

    /// The items of a [`Value::Array`].
    #[must_use]
    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Self::Array(items) => Some(items),
            _ => None,
        }
    }

    /// The entries of a [`Value::Object`], in parse order.
    #[must_use]
    pub fn as_object(&self) -> Option<&[(String, Value)]> {
        match self {
            Self::Object(entries) => Some(entries),
            _ => None,
        }
    }
}

/// Largest and smallest integers the protocol allows (`PROTOCOL.md` 3.2).
pub const MAX_INT: i64 = (1 << 53) - 1;
/// See [`MAX_INT`].
pub const MIN_INT: i64 = -((1 << 53) - 1);

// --------------------------------------------------------------------------- //
// serializing
// --------------------------------------------------------------------------- //

/// Compare two keys the way RFC 8785 does: by UTF-16 code unit.
///
/// `"\u{10000}"` sorts **before** `"\u{ffff}"` here, the opposite of code point
/// order, because its first code unit is the surrogate `0xD800`.
#[must_use]
pub fn key_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

/// Serialize `value` to canonical JSON text under `limits`.
pub fn to_canonical_with(value: &Value, limits: &Limits) -> Result<String> {
    let mut out = String::new();
    write_value(value, 1, limits, &mut out)?;
    if out.len() > limits.max_bytes {
        return Err(CanonicalError::new(
            Reason::SizeExceeded,
            format!("{} bytes", out.len()),
        ));
    }
    Ok(out)
}

/// Serialize `value` under the protocol limits.
pub fn to_canonical(value: &Value) -> Result<String> {
    to_canonical_with(value, &Limits::protocol())
}

/// The canonical UTF-8 bytes of `value`: the exact bytes that get hashed.
pub fn canonical_bytes(value: &Value) -> Result<Vec<u8>> {
    Ok(to_canonical(value)?.into_bytes())
}

/// `SHA-256` of the canonical bytes, lowercase hex.
pub fn canonical_sha256_hex(value: &Value) -> Result<String> {
    let bytes = canonical_bytes(value)?;
    Ok(hex_lower(&Sha256::digest(&bytes)))
}

fn write_value(value: &Value, depth: usize, limits: &Limits, out: &mut String) -> Result<()> {
    if depth > limits.max_depth {
        return Err(CanonicalError::new(
            Reason::DepthExceeded,
            format!("depth {depth}"),
        ));
    }
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Int(i) => {
            if !(MIN_INT..=MAX_INT).contains(i) {
                return Err(CanonicalError::new(Reason::IntOutOfRange, i.to_string()));
            }
            out.push_str(&i.to_string());
        }
        Value::Str(s) => write_string(s, limits, out)?,
        Value::Array(items) => {
            out.push('[');
            for (n, item) in items.iter().enumerate() {
                if n > 0 {
                    out.push(',');
                }
                write_value(item, depth + 1, limits, out)?;
            }
            out.push(']');
        }
        Value::Object(entries) => {
            let mut sorted: Vec<&(String, Value)> = entries.iter().collect();
            sorted.sort_by(|a, b| key_cmp(&a.0, &b.0));
            // A duplicate key would make the canonical form ambiguous.
            for pair in sorted.windows(2) {
                if let [a, b] = pair {
                    if a.0 == b.0 {
                        return Err(CanonicalError::new(Reason::DuplicateKey, a.0.clone()));
                    }
                }
            }
            out.push('{');
            for (n, (key, val)) in sorted.iter().map(|p| (&p.0, &p.1)).enumerate() {
                if n > 0 {
                    out.push(',');
                }
                write_string(key, limits, out)?;
                out.push(':');
                write_value(val, depth + 1, limits, out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

fn write_string(s: &str, limits: &Limits, out: &mut String) -> Result<()> {
    if s.len() > limits.max_string_bytes {
        return Err(CanonicalError::new(
            Reason::StringTooLong,
            format!("{} bytes", s.len()),
        ));
    }
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{9}' => out.push_str("\\t"),
            '\u{a}' => out.push_str("\\n"),
            '\u{c}' => out.push_str("\\f"),
            '\u{d}' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => {
                // Lowercase hex, four digits, as RFC 8785 requires.
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            // Everything else, including non-ASCII, is emitted literally.
            c => out.push(c),
        }
    }
    out.push('"');
    Ok(())
}

/// Lowercase hex with no prefix and no separators (`PROTOCOL.md` section 1).
#[must_use]
pub fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Decode lowercase hex. Rejects uppercase, odd length and non-hex digits.
pub fn hex_decode(text: &str) -> std::result::Result<Vec<u8>, &'static str> {
    if !text.len().is_multiple_of(2) {
        return Err("NOT_HEX");
    }
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(text.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_digit(bytes[i])?;
        let lo = hex_digit(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

fn hex_digit(byte: u8) -> std::result::Result<u8, &'static str> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err("NOT_HEX"),
    }
}

// --------------------------------------------------------------------------- //
// parsing
// --------------------------------------------------------------------------- //

/// Parse `bytes` under `limits`, rejecting anything non-canonical in form.
pub fn parse_bytes(bytes: &[u8], limits: &Limits) -> Result<Value> {
    if bytes.len() > limits.max_bytes {
        return Err(CanonicalError::new(
            Reason::SizeExceeded,
            format!("{} bytes", bytes.len()),
        ));
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|e| CanonicalError::new(Reason::InvalidUtf8, e.to_string()))?;
    parse_str(text, limits)
}

/// Parse `text` under `limits`.
pub fn parse_str(text: &str, limits: &Limits) -> Result<Value> {
    if text.len() > limits.max_bytes {
        return Err(CanonicalError::new(
            Reason::SizeExceeded,
            format!("{} bytes", text.len()),
        ));
    }
    let mut p = Parser {
        input: text.as_bytes(),
        pos: 0,
        limits,
    };
    p.skip_ws();
    let value = p.parse_value(1)?;
    p.skip_ws();
    if p.pos != p.input.len() {
        return Err(CanonicalError::new(
            Reason::TrailingData,
            format!("at byte {}", p.pos),
        ));
    }
    Ok(value)
}

/// Parse under the protocol limits.
pub fn parse(text: &str) -> Result<Value> {
    parse_str(text, &Limits::protocol())
}

/// True when `text` is exactly the canonical form of its own value.
///
/// The signer uses this: re-canonicalizing an accepted event must give back
/// identical bytes (`PROTOCOL.md` 11.2 item 4).
#[must_use]
pub fn is_canonical(text: &str) -> bool {
    match parse(text) {
        Ok(value) => to_canonical(&value).map(|c| c == text).unwrap_or(false),
        Err(_) => false,
    }
}

struct Parser<'a> {
    input: &'a [u8],
    pos: usize,
    limits: &'a Limits,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.input.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let b = self.peek();
        if b.is_some() {
            self.pos += 1;
        }
        b
    }

    fn skip_ws(&mut self) {
        while let Some(b) = self.peek() {
            // RFC 8259 whitespace only.
            if matches!(b, b' ' | b'\t' | b'\n' | b'\r') {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn err<T>(&self, reason: Reason, detail: impl Into<String>) -> Result<T> {
        Err(CanonicalError::new(reason, detail))
    }

    fn expect(&mut self, want: u8) -> Result<()> {
        if self.bump() == Some(want) {
            Ok(())
        } else {
            self.err(Reason::SyntaxError, format!("expected {}", want as char))
        }
    }

    fn literal(&mut self, word: &str) -> Result<()> {
        if self.input.len() >= self.pos + word.len()
            && &self.input[self.pos..self.pos + word.len()] == word.as_bytes()
        {
            self.pos += word.len();
            Ok(())
        } else {
            self.err(Reason::SyntaxError, format!("expected {word}"))
        }
    }

    fn parse_value(&mut self, depth: usize) -> Result<Value> {
        if depth > self.limits.max_depth {
            return self.err(Reason::DepthExceeded, format!("depth {depth}"));
        }
        match self.peek() {
            None => self.err(Reason::SyntaxError, "empty input"),
            Some(b'{') => self.parse_object(depth),
            Some(b'[') => self.parse_array(depth),
            Some(b'"') => Ok(Value::Str(self.parse_string()?)),
            Some(b't') => {
                self.literal("true")?;
                Ok(Value::Bool(true))
            }
            Some(b'f') => {
                self.literal("false")?;
                Ok(Value::Bool(false))
            }
            Some(b'n') => {
                self.literal("null")?;
                Ok(Value::Null)
            }
            // The three non-JSON literals JSON5 and Python allow; named so the
            // rejection is specific rather than a generic syntax error.
            Some(b'N') => self.err(Reason::NanOrInfinity, "NaN"),
            Some(b'I') => self.err(Reason::NanOrInfinity, "Infinity"),
            Some(b'-') if self.input.get(self.pos + 1) == Some(&b'I') => {
                self.err(Reason::NanOrInfinity, "-Infinity")
            }
            Some(b'-' | b'0'..=b'9') => self.parse_number(),
            Some(b'+') => self.err(Reason::NumberFormInvalid, "+"),
            Some(other) => self.err(Reason::SyntaxError, format!("unexpected {}", other as char)),
        }
    }

    fn parse_object(&mut self, depth: usize) -> Result<Value> {
        self.expect(b'{')?;
        let mut entries: Vec<(String, Value)> = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(Value::Object(entries));
        }
        loop {
            self.skip_ws();
            if self.peek() != Some(b'"') {
                return self.err(Reason::SyntaxError, "object key must be a string");
            }
            let key = self.parse_string()?;
            if entries.iter().any(|(k, _)| *k == key) {
                return self.err(Reason::DuplicateKey, key);
            }
            self.skip_ws();
            self.expect(b':')?;
            self.skip_ws();
            let value = self.parse_value(depth + 1)?;
            entries.push((key, value));
            self.skip_ws();
            match self.bump() {
                Some(b',') => {}
                Some(b'}') => return Ok(Value::Object(entries)),
                _ => return self.err(Reason::SyntaxError, "expected , or }"),
            }
        }
    }

    fn parse_array(&mut self, depth: usize) -> Result<Value> {
        self.expect(b'[')?;
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(Value::Array(items));
        }
        loop {
            self.skip_ws();
            items.push(self.parse_value(depth + 1)?);
            self.skip_ws();
            match self.bump() {
                Some(b',') => {}
                Some(b']') => return Ok(Value::Array(items)),
                _ => return self.err(Reason::SyntaxError, "expected , or ]"),
            }
        }
    }

    fn parse_string(&mut self) -> Result<String> {
        self.expect(b'"')?;
        let mut out = String::new();
        loop {
            let byte = match self.bump() {
                Some(b) => b,
                None => return self.err(Reason::SyntaxError, "unterminated string"),
            };
            match byte {
                b'"' => break,
                b'\\' => {
                    let esc = match self.bump() {
                        Some(b) => b,
                        None => return self.err(Reason::SyntaxError, "truncated escape"),
                    };
                    match esc {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => out.push(self.parse_unicode_escape()?),
                        other => {
                            return self
                                .err(Reason::SyntaxError, format!("bad escape {}", other as char))
                        }
                    }
                }
                b if b < 0x20 => {
                    return self.err(Reason::SyntaxError, "raw control character in string")
                }
                b if b < 0x80 => out.push(b as char),
                _ => {
                    // Multi-byte UTF-8: the whole input was validated as UTF-8,
                    // so decode the sequence starting here.
                    let start = self.pos - 1;
                    let len = utf8_len(byte);
                    let end = start + len;
                    let slice = self
                        .input
                        .get(start..end)
                        .ok_or_else(|| CanonicalError::new(Reason::InvalidUtf8, "truncated"))?;
                    let text = std::str::from_utf8(slice)
                        .map_err(|e| CanonicalError::new(Reason::InvalidUtf8, e.to_string()))?;
                    out.push_str(text);
                    self.pos = end;
                }
            }
            if out.len() > self.limits.max_string_bytes {
                return self.err(
                    Reason::StringTooLong,
                    format!("over {} bytes", self.limits.max_string_bytes),
                );
            }
        }
        if out.len() > self.limits.max_string_bytes {
            return self.err(Reason::StringTooLong, format!("{} bytes", out.len()));
        }
        Ok(out)
    }

    fn parse_hex4(&mut self) -> Result<u16> {
        let slice = self
            .input
            .get(self.pos..self.pos + 4)
            .ok_or_else(|| CanonicalError::new(Reason::SyntaxError, "truncated \\u escape"))?;
        let mut value: u16 = 0;
        for b in slice {
            let digit = match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => b - b'a' + 10,
                b'A'..=b'F' => b - b'A' + 10,
                _ => return self.err(Reason::SyntaxError, "bad \\u escape"),
            };
            value = value * 16 + u16::from(digit);
        }
        self.pos += 4;
        Ok(value)
    }

    fn parse_unicode_escape(&mut self) -> Result<char> {
        let first = self.parse_hex4()?;
        if (0xD800..=0xDBFF).contains(&first) {
            // High surrogate: a low surrogate must follow immediately.
            if self.peek() == Some(b'\\') && self.input.get(self.pos + 1) == Some(&b'u') {
                self.pos += 2;
                let second = self.parse_hex4()?;
                if !(0xDC00..=0xDFFF).contains(&second) {
                    return self.err(Reason::LoneSurrogate, format!("U+{first:04X}"));
                }
                let combined =
                    0x1_0000 + ((u32::from(first) - 0xD800) << 10) + (u32::from(second) - 0xDC00);
                return char::from_u32(combined)
                    .ok_or_else(|| CanonicalError::new(Reason::LoneSurrogate, "bad pair"));
            }
            return self.err(Reason::LoneSurrogate, format!("U+{first:04X}"));
        }
        if (0xDC00..=0xDFFF).contains(&first) {
            return self.err(Reason::LoneSurrogate, format!("U+{first:04X}"));
        }
        char::from_u32(u32::from(first))
            .ok_or_else(|| CanonicalError::new(Reason::SyntaxError, "bad code point"))
    }

    fn parse_number(&mut self) -> Result<Value> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        while matches!(
            self.peek(),
            Some(b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-')
        ) {
            self.pos += 1;
        }
        let token = std::str::from_utf8(
            self.input
                .get(start..self.pos)
                .ok_or_else(|| CanonicalError::new(Reason::SyntaxError, "number"))?,
        )
        .map_err(|e| CanonicalError::new(Reason::InvalidUtf8, e.to_string()))?;
        check_number_token(token)?;
        let parsed: i64 = token
            .parse()
            .map_err(|_| CanonicalError::new(Reason::IntOutOfRange, token.to_owned()))?;
        if !(MIN_INT..=MAX_INT).contains(&parsed) {
            return self.err(Reason::IntOutOfRange, token.to_owned());
        }
        Ok(Value::Int(parsed))
    }
}

fn utf8_len(first: u8) -> usize {
    match first {
        0x00..=0x7F => 1,
        0xC0..=0xDF => 2,
        0xE0..=0xEF => 3,
        _ => 4,
    }
}

/// Check a number token against `PROTOCOL.md` 3.2.
///
/// The order of the checks decides which code a caller sees, and the vectors
/// pin it: `-0` is [`Reason::MinusZero`], `01` is [`Reason::LeadingZero`],
/// `1.5` and `1e2` are [`Reason::FloatNotAllowed`], `+1` is
/// [`Reason::NumberFormInvalid`].
pub fn check_number_token(token: &str) -> Result<()> {
    if token == "-0" {
        return Err(CanonicalError::new(Reason::MinusZero, token.to_owned()));
    }
    let digits = token.strip_prefix('-').unwrap_or(token);
    if digits.len() > 1 && digits.starts_with('0') && digits.as_bytes()[1].is_ascii_digit() {
        return Err(CanonicalError::new(Reason::LeadingZero, token.to_owned()));
    }
    let canonical_form = !digits.is_empty()
        && digits.bytes().all(|b| b.is_ascii_digit())
        && (digits == "0" || !digits.starts_with('0'));
    if canonical_form {
        return Ok(());
    }
    if token.contains('.') || token.contains('e') || token.contains('E') {
        return Err(CanonicalError::new(
            Reason::FloatNotAllowed,
            token.to_owned(),
        ));
    }
    Err(CanonicalError::new(
        Reason::NumberFormInvalid,
        token.to_owned(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obj(pairs: &[(&str, Value)]) -> Value {
        Value::Object(
            pairs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), v.clone()))
                .collect(),
        )
    }

    #[test]
    fn keys_sort_by_utf16_code_unit_not_code_point() {
        // U+10000 is the surrogate pair D800 DC00, so it sorts before U+FFFF.
        let value = obj(&[("\u{ffff}", Value::Int(1)), ("\u{10000}", Value::Int(2))]);
        let canonical = to_canonical(&value).unwrap();
        let first_key_pos = canonical.find('\u{10000}').unwrap();
        let second_key_pos = canonical.find('\u{ffff}').unwrap();
        assert!(first_key_pos < second_key_pos, "{canonical}");
        // And the naive ordering is genuinely different.
        let mut naive = vec!["\u{ffff}", "\u{10000}"];
        naive.sort_unstable();
        assert_eq!(naive, vec!["\u{ffff}", "\u{10000}"]);
    }

    #[test]
    fn integers_at_the_boundary_round_trip() {
        for i in [0_i64, 1, -1, MAX_INT, MIN_INT] {
            let text = to_canonical(&Value::Int(i)).unwrap();
            assert_eq!(parse(&text).unwrap(), Value::Int(i));
        }
    }

    #[test]
    fn integers_outside_the_range_are_rejected() {
        let err = to_canonical(&Value::Int(MAX_INT + 1)).unwrap_err();
        assert_eq!(err.reason, Reason::IntOutOfRange);
        let err = parse("9007199254740992").unwrap_err();
        assert_eq!(err.reason, Reason::IntOutOfRange);
    }

    #[test]
    fn number_token_codes_match_the_protocol_table() {
        let cases = [
            ("-0", Reason::MinusZero),
            ("01", Reason::LeadingZero),
            ("-01", Reason::LeadingZero),
            ("1.5", Reason::FloatNotAllowed),
            ("1e2", Reason::FloatNotAllowed),
            ("1E2", Reason::FloatNotAllowed),
            ("--1", Reason::NumberFormInvalid),
        ];
        for (token, reason) in cases {
            assert_eq!(
                check_number_token(token).unwrap_err().reason,
                reason,
                "{token}"
            );
        }
        assert!(check_number_token("0").is_ok());
        assert!(check_number_token("-12").is_ok());
    }

    #[test]
    fn duplicate_keys_are_rejected_on_both_sides() {
        assert_eq!(
            parse(r#"{"a":1,"a":2}"#).unwrap_err().reason,
            Reason::DuplicateKey
        );
        let value = Value::Object(vec![
            ("a".to_owned(), Value::Int(1)),
            ("a".to_owned(), Value::Int(2)),
        ]);
        assert_eq!(
            to_canonical(&value).unwrap_err().reason,
            Reason::DuplicateKey
        );
    }

    #[test]
    fn lone_surrogates_are_rejected_and_pairs_are_accepted() {
        assert_eq!(
            parse(r#""\ud800""#).unwrap_err().reason,
            Reason::LoneSurrogate
        );
        assert_eq!(
            parse(r#""\udc00""#).unwrap_err().reason,
            Reason::LoneSurrogate
        );
        assert_eq!(
            parse(r#""\ud800a""#).unwrap_err().reason,
            Reason::LoneSurrogate
        );
        assert_eq!(
            parse(r#""😀""#).unwrap(),
            Value::Str("\u{1f600}".to_owned())
        );
    }

    #[test]
    fn invalid_utf8_is_rejected() {
        let err = parse_bytes(b"{\"a\":\"\xff\xfe\"}", &Limits::protocol()).unwrap_err();
        assert_eq!(err.reason, Reason::InvalidUtf8);
    }

    #[test]
    fn trailing_data_and_syntax_errors_are_distinguished() {
        assert_eq!(parse("{} {}").unwrap_err().reason, Reason::TrailingData);
        assert_eq!(parse("{").unwrap_err().reason, Reason::SyntaxError);
    }

    #[test]
    fn depth_limit_applies_to_parsing_and_serializing() {
        let deep_ok = format!("{}{}", "[".repeat(16), "]".repeat(16));
        assert!(parse(&deep_ok).is_ok());
        let too_deep = format!("{}{}", "[".repeat(17), "]".repeat(17));
        assert_eq!(parse(&too_deep).unwrap_err().reason, Reason::DepthExceeded);
    }

    #[test]
    fn string_limit_is_in_bytes() {
        let limits = Limits::protocol();
        let long = "x".repeat(limits.max_string_bytes + 1);
        let err = to_canonical(&Value::Str(long)).unwrap_err();
        assert_eq!(err.reason, Reason::StringTooLong);
    }

    #[test]
    fn nan_and_infinity_get_their_own_code() {
        assert_eq!(
            parse(r#"{"a":NaN}"#).unwrap_err().reason,
            Reason::NanOrInfinity
        );
        assert_eq!(
            parse(r#"{"a":Infinity}"#).unwrap_err().reason,
            Reason::NanOrInfinity
        );
        assert_eq!(
            parse(r#"{"a":-Infinity}"#).unwrap_err().reason,
            Reason::NanOrInfinity
        );
    }

    #[test]
    fn plus_sign_is_a_number_form_error_not_a_syntax_error() {
        assert_eq!(
            parse(r#"{"a":+1}"#).unwrap_err().reason,
            Reason::NumberFormInvalid
        );
    }

    #[test]
    fn escaping_matches_rfc_8785() {
        let value = Value::Str("a\"b\\c\u{8}\u{c}\n\r\t\u{1f}d".to_owned());
        assert_eq!(
            to_canonical(&value).unwrap(),
            "\"a\\\"b\\\\c\\b\\f\\n\\r\\t\\u001fd\""
        );
        // Non-ASCII stays literal.
        assert_eq!(
            to_canonical(&Value::Str("\u{e9}\u{4e2d}".to_owned())).unwrap(),
            "\"\u{e9}\u{4e2d}\""
        );
    }

    #[test]
    fn is_canonical_rejects_whitespace_and_wrong_key_order() {
        assert!(is_canonical(r#"{"a":1,"b":2}"#));
        assert!(!is_canonical(r#"{"b":2,"a":1}"#));
        assert!(!is_canonical(r#"{"a": 1}"#));
        assert!(is_canonical("[]"));
    }

    #[test]
    fn hex_helpers_are_lowercase_only() {
        assert_eq!(hex_lower(&[0x00, 0x0f, 0xff]), "000fff");
        assert_eq!(hex_decode("000fff").unwrap(), vec![0x00, 0x0f, 0xff]);
        assert!(hex_decode("00FF").is_err());
        assert!(hex_decode("0").is_err());
        assert!(hex_decode("zz").is_err());
    }
}
