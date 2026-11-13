//! Kernel command line: the one quote-aware tokenizer shared by i7lab-init and i7labd (review feasibility F13).
//! Owner: P2.

/// Split like the kernel does: whitespace separates words, double quotes group (quotes removed).
pub fn tokenize(cmdline: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut any = false;
    for ch in cmdline.chars() {
        match ch {
            '"' => {
                quoted = !quoted;
                any = true;
            }
            c if c.is_whitespace() && !quoted => {
                if any {
                    out.push(std::mem::take(&mut cur));
                    any = false;
                }
            }
            c => {
                cur.push(c);
                any = true;
            }
        }
    }
    if any {
        out.push(cur);
    }
    out
}

/// `i7lab.<key>=<value>` pairs in order (later ones win when applied in order). `i7lab.flag` alone => value "1".
pub fn i7lab_args(cmdline: &str) -> Vec<(String, String)> {
    tokenize(cmdline)
        .into_iter()
        .filter_map(|w| {
            let rest = w.strip_prefix("i7lab.")?.to_string();
            Some(match rest.split_once('=') {
                Some((k, v)) => (k.to_string(), v.to_string()),
                None => (rest, "1".to_string()),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn quotes_and_flags() {
        assert_eq!(tokenize(r#"a  "b c" d="e f"g"#), vec!["a", "b c", "d=e fg"]);
        let a = i7lab_args(r#"quiet i7lab.http=off i7lab.hostname="lab one" i7lab.debug"#);
        assert_eq!(a, vec![("http".into(), "off".into()), ("hostname".into(), "lab one".into()), ("debug".into(), "1".into())]);
    }
}
