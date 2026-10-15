//! Random charclass URL templating: `/api/[a-z][1-9]?q=[a-f0-9]`.
//!
//! Grammar: literal text runs puncuated with `[...]` charclasses. Classes are
//! unions of ranges `a-z`, `0-9`, `A-F`, optionally single chars, escaped by
//! `\[`. Expanding samples one uniformly random char per range per request.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Seg {
    Lit(String),
    Class(Vec<char>),
}

#[derive(Debug, Clone, Default)]
pub struct UrlTemplate {
    segments: Vec<Seg>,
}

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
}
