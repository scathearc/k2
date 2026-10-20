//! Random charclass templating: `/api/[a-z][1-9]?q=[a-f0-9]` for URLs and
//! `{"user": "[a-z][a-z][0-9]"}` for request bodies.
//!
//! Grammar: literal text runs puncuated with `[...]` charclasses. Classes are
//! unions of ranges `a-z`, `0-9`, `A-F`, optionally single chars, escaped by
//! `\[`. Expanding samples one uniformly random char per range per request.
//!
//! Body mode (`parse_body`) is JSON-safe: a `[...]` group only counts as a
//! charclass when its content is pure class atoms; anything else (JSON arrays
//! like `[1,2,3]`, empty `[]`, quoted strings, whitespace) stays literal.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Seg {
    Lit(String),
    Class(Vec<char>),
}

#[derive(Debug, Clone, Default)]
pub struct UrlTemplate {
    segments: Vec<Seg>,
}

/// Alias for body templating — same engine, JSON-safe parser (`parse_body`).
pub type BodyTemplate = UrlTemplate;

impl UrlTemplate {
    /// Parse a path+query suffix (no scheme/authority) into template segments.
    pub fn parse(s: &str) -> Result<Self, String> {
        let mut segments = Vec::new();
        let mut lit = String::new();
        let mut chars = s.chars().peekable();
        while let Some(&c) = chars.peek() {
            match c {
                '[' => {
                    chars.next();
                    if !lit.is_empty() {
                        // avoid an empty-literal zero segment
                        segments.push(Seg::Lit(std::mem::take(&mut lit)));
                    }
                    let mut class = Vec::new();
                    let mut closed = false;
                    while let Some(ch) = chars.next() {
                        match ch {
                            ']' => {
                                closed = true;
                                break;
                            }
                            '\\' => {
                                if let Some(esc) = chars.next() {
                                    class.push(esc);
                                }
                            }
                            _ => {
                                // range?  a-z
                                if chars.peek() == Some(&'-') {
                                    chars.next(); // consume '-'
                                    let Some(hi) = chars.next() else {
                                        return Err("truncated charclass".into());
                                    };
                                    if hi == ']' {
                                        class.push('-');
                                        closed = true;
                                        break;
                                    }
                                    (chars_range(&mut class, ch, hi))?;
                                } else {
                                    class.push(ch);
                                }
                            }
                        }
                    }
                    if !closed {
                        return Err("unclosed charclass".into());
                    }
                    if class.is_empty() {
                        return Err("empty charclass".into());
                    }
                    segments.push(Seg::Class(class));
                }
                '\\' => {
                    chars.next();
                    if let Some(esc) = chars.next() {
                        lit.push(esc);
                    }
                }
                _ => {
                    lit.push(c);
                    chars.next();
                }
            }
        }
        if !lit.is_empty() {
            segments.push(Seg::Lit(lit));
        }
        Ok(Self { segments })
    }

    /// True when the template contains at least one class (needs expansion).
    pub fn has_variables(&self) -> bool {
        self.segments.iter().any(|s| matches!(s, Seg::Class(_)))
    }

    /// Parse a request body template (JSON-safe). Same charclass grammar as
    /// URLs, but a `[...]` group is only a class when every atom is a plain
    /// class char (alphanumeric, `-`, or `\`-escaped). Groups containing
    /// structural JSON punctuation (`,{}[]"'` or whitespace/control chars)
    /// are kept as literal text, so bodies like `{"items": [1,2,3]}` pass
    /// through untouched. Never errors — malformed groups go literal.
    pub fn parse_body(s: &str) -> Self {
        let mut segments = Vec::new();
        let mut lit = String::new();
        let mut chars = s.chars().peekable();
        while let Some(&c) = chars.peek() {
            if c == '\\' {
                // Escape in literal context: next char is literal (`\[` → `[`).
                chars.next();
                match chars.next() {
                    Some(e) => lit.push(e),
                    None => lit.push('\\'),
                }
                continue;
            }
            if c != '[' {
                lit.push(c);
                chars.next();
                continue;
            }
            // Scan on a clone so a failed (literal) group leaves `chars`
            // untouched; commit the clone wholesale on success.
            let mut probe = chars.clone();
            match try_scan_class(&mut probe) {
                Some(class) => {
                    chars = probe;
                    if !lit.is_empty() {
                        segments.push(Seg::Lit(std::mem::take(&mut lit)));
                    }
                    segments.push(Seg::Class(class));
                }
                None => {
                    // Not a class: the opening '[' was literal; scanning
                    // resumes at the next char.
                    lit.push('[');
                    chars.next();
                }
            }
        }
        if !lit.is_empty() {
            segments.push(Seg::Lit(lit));
        }
        Self { segments }
    }

    /// Expand with fresh random samples per class.
    pub fn expand(&self) -> String {
        let mut out = String::with_capacity(64);
        for seg in &self.segments {
            match seg {
                Seg::Lit(l) => out.push_str(l),
                Seg::Class(cs) => {
                    // unbiased per-char pick
                    let idx = rand::random_range(0..cs.len());
                    out.push(cs[idx]);
                }
            }
        }
        out
    }
}

fn chars_range(vec: &mut Vec<char>, lo: char, hi: char) -> Result<(), String> {
    let (alo, ahi) = (lo as u32, hi as u32);
    if ahi < alo {
        return Err(format!("charclass range descending: {lo}-{hi}"));
    }
    if ahi - alo > 65535 {
        return Err("charclass range too large".into());
    }
    for c in (alo..=ahi).filter_map(std::char::from_u32) {
        vec.push(c);
    }
    Ok(())
}

/// JSON punctuation that disqualifies a `[...]` group from being a charclass
/// in body mode.
fn is_structural(c: char) -> bool {
    matches!(c, ',' | '{' | '}' | '[' | ']' | '"' | '\'') || c.is_whitespace() || c.is_control()
}

/// Scan a `[...]` group starting at the peeked `[`. Returns `Some(class)` when
/// the group is a well-formed charclass (consuming it), `None` when it must
/// stay literal (leaving the `[` unconsumed). Ranges with structural bounds or
/// descending order also fall back to literal — body mode is total.
fn try_scan_class(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) -> Option<Vec<char>> {
    chars.next(); // consume '['
    let mut class = Vec::new();
    loop {
        let ch = chars.next()?;
        match ch {
            ']' => return if class.is_empty() { None } else { Some(class) },
            '\\' => {
                // Escaped member: any char is allowed (e.g. `\,`). A dangling
                // escape means this was never a class.
                class.push(chars.next()?);
            }
            _ => {
                if is_structural(ch) {
                    return None;
                }
                if chars.peek() == Some(&'-') {
                    let mut probe = chars.clone();
                    probe.next(); // '-'
                    match probe.next() {
                        None => return None, // `[a-` unterminated
                        Some(']') => {
                            // trailing `-` is a literal member: `[a-]`
                            chars.next();
                            class.push('-');
                        }
                        Some(hi) => {
                            if is_structural(hi) {
                                return None;
                            }
                            chars_range(&mut class, ch, hi).ok()?;
                            chars.next(); // '-'
                            chars.next(); // hi
                        }
                    }
                } else {
                    class.push(ch);
                }
            }
        }
    }
}

/// Split a full URL into (origin_prefix, path+query suffix) for templating.
pub fn split_origin(raw: &str) -> (String, String) {
    // find "//" to know authority end
    match raw.find("://") {
        Some(rest) => {
            let after = &raw[rest + 3..];
            match after.find('/') {
                Some(i) => {
                    let origin = &raw[..rest + 3 + i];
                    (origin.to_string(), after[i..].to_string())
                }
                None => (raw.to_string(), String::new()),
            }
        }
        None => (String::new(), raw.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_charclass() {
        let t = UrlTemplate::parse("/api/v1/someEndpoint?query=[a-z][1-9]").unwrap();
        assert!(t.has_variables());
        let a = t.expand();
        let b = t.expand();
        assert!(a.starts_with("/api/v1/someEndpoint?query="));
        assert_eq!(a.len(), b.len());
    }

    #[test]
    fn range_expansion_letters() {
        let t = UrlTemplate::parse("[a-d]").unwrap();
        for _ in 0..64 {
            let s = t.expand().chars().next().unwrap();
            assert!(['a', 'b', 'c', 'd'].contains(&s), "got {s}");
        }
    }

    #[test]
    fn literal_no_class() {
        let t = UrlTemplate::parse("/plain/path").unwrap();
        assert_eq!(t.expand(), "/plain/path");
        assert!(!t.has_variables());
    }

    #[test]
    fn rejects_unclosed() {
        assert!(UrlTemplate::parse("/x[abc").is_err());
        assert!(UrlTemplate::parse("/x[9-1]").is_err());
    }

    #[test]
    fn union_multi_ranges() {
        let t = UrlTemplate::parse("[0-9a-f]").unwrap();
        for _ in 0..256 {
            let c = t.expand().chars().next().unwrap();
            assert!(c.is_ascii_hexdigit(), "got {c}");
        }
    }

    #[test]
    fn origin_spliterator() {
        let (o, p) = split_origin("https://api.t.local/api/[a-z]");
        assert_eq!(o, "https://api.t.local");
        assert_eq!(p, "/api/[a-z]");
        let (o2, p2) = split_origin("/tmp/rel");
        assert_eq!(o2, "");
        assert_eq!(p2, "/tmp/rel");
    }

    #[test]
    fn body_mode_expands_classes() {
        let t = UrlTemplate::parse_body("{\"username\": \"[a-z][a-z][a-z][0-9][0-9]\"}");
        assert!(t.has_variables());
        let mut seen = std::collections::HashSet::new();
        for _ in 0..128 {
            let s = t.expand();
            let u: Vec<char> = s.split(": ").nth(1).unwrap().chars().collect();
            assert_eq!(u.len(), 8, "s: {s}"); // quote + 5 class chars + quote + }
            assert_eq!(u[0], '"');
            assert!(u[1..4].iter().all(|c| c.is_ascii_lowercase()));
            assert!(u[4..6].iter().all(|c| c.is_ascii_digit()));
            assert_eq!(u[6], '"');
            assert_eq!(u[7], '}');
            seen.insert(s);
        }
        assert!(seen.len() > 1, "expansion must vary");
    }

    #[test]
    fn body_mode_keeps_json_literals() {
        // JSON arrays, empty arrays, quoted arrays with whitespace: literal.
        for body in [
            "{\"items\": [1,2,3]}",
            "{\"items\": []}",
            "{\"xs\": [1, 2, 3], \"n\": 4}",
            "{\"a\": [{\"b\": 1}]}",
            "[]",
        ] {
            let t = UrlTemplate::parse_body(body);
            assert!(!t.has_variables(), "{body}");
            assert_eq!(t.expand(), body);
        }
    }

    #[test]
    fn body_mode_mixed_class_and_array() {
        let body = "{\"u\":\"[a-z][0-9]\",\"arr\":[7,8]}";
        let t = UrlTemplate::parse_body(body);
        assert!(t.has_variables());
        for _ in 0..32 {
            let s = t.expand();
            assert!(s.ends_with(",\"arr\":[7,8]}"), "s: {s}");
            let u = s.split(":\"").nth(1).unwrap();
            let u = &u[..2];
            assert!(u.as_bytes()[0].is_ascii_lowercase());
            assert!(u.as_bytes()[1].is_ascii_digit());
        }
    }

    #[test]
    fn body_mode_edges() {
        // Unclosed group → literal. Escapes work. `[a-]` keeps literal dash.
        assert_eq!(UrlTemplate::parse_body("[abc").expand(), "[abc");
        assert_eq!(UrlTemplate::parse_body("[9-1]").expand(), "[9-1]");
        assert_eq!(UrlTemplate::parse_body("\\[a-z\\]").expand(), "[a-z]");
        assert_eq!(UrlTemplate::parse_body("[]").expand(), "[]");
        let dash = UrlTemplate::parse_body("[a-]").expand();
        assert_eq!(dash.len(), 1);
        assert!(dash == "a" || dash == "-", "got {dash}");
        // Escaped comma inside a class is a member.
        let t = UrlTemplate::parse_body("[a\\,b]");
        assert!(matches!(t.segments.as_slice(), [Seg::Class(cs)] if cs.len() == 3));
    }

    #[test]
    fn body_mode_union_multi_range() {
        let t = UrlTemplate::parse_body("[0-9a-fA-F]");
        for _ in 0..256 {
            let c = t.expand().chars().next().unwrap();
            assert!(c.is_ascii_hexdigit(), "got {c}");
        }
    }
}
