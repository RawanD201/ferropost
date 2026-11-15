//! Contact rules.

/// Parses a pasted list of addresses (Go's `parseEmailList`): split on new
/// lines, commas and semicolons, trim, lowercase, keep entries containing
/// `@` and `.`, and drop duplicates while keeping the first-seen order.
pub fn parse_email_list(data: &str) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    data.split(['\n', '\r', ',', ';'])
        .map(|line| line.trim().to_lowercase())
        .filter(|email| !email.is_empty() && email.contains('@') && email.contains('.'))
        .filter(|email| seen.insert(email.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_like_go() {
        let parsed = parse_email_list(
            " A@Example.com\r\nb@example.com;c@example.com, a@example.com\nnot-an-email\n\n",
        );
        assert_eq!(parsed, ["a@example.com", "b@example.com", "c@example.com"]);
        assert!(parse_email_list("").is_empty());
        assert!(parse_email_list("nobody@localhost").is_empty());
    }
}
