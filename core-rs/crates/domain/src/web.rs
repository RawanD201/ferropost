//! Rules for the public web surface: base path, safe entrance, public paths.

/// Normalises `WEB_BASE_PATH`/`PUBLIC_PATH` the same way Go's
/// `normalizeWebBasePath` does: returns `""` for root or invalid input,
/// otherwise `/segment[/segment...]` without a trailing slash.
pub fn normalize_base_path(path: &str) -> String {
    let path = path.trim();
    if path.is_empty() || path == "/" || path.contains('\\') || path.contains("..") {
        return String::new();
    }
    let normalized = format!("/{}", path.trim_matches('/'));
    if normalized.contains("//") {
        return String::new();
    }
    normalized
}

/// Strips the base path from a request path. Returns `None` when the path is
/// outside the base path (left untouched, like Go).
pub fn strip_base_path<'a>(base: &str, path: &'a str) -> Option<&'a str> {
    if base.is_empty() {
        return None;
    }
    if path == base {
        return Some("/");
    }
    path.strip_prefix(base).filter(|rest| rest.starts_with('/'))
}

/// Root URL of the console under the base path (`/` or `/base/`).
pub fn base_root(base: &str) -> String {
    if base.is_empty() {
        "/".to_owned()
    } else {
        format!("{base}/")
    }
}

/// Paths that must stay reachable without the safe entrance or IP whitelist:
/// subscribe/unsubscribe flows, the public send API and their static pages.
/// Copied from Go's `excludesURIs` in `cmd.go`.
pub const PUBLIC_EXACT_PATHS: &[&str] = &[
    "/favicon.ico",
    "/robots.txt",
    "/unsubscribe.html",
    "/unsubscribe_new.html",
    "/api/aapanel/sso",
    "/api/unsubscribe/user_group",
    "/api/unsubscribe",
    // RFC 8058 one-click target of the List-Unsubscribe header (Ferropost).
    "/api/unsubscribe/one_click",
    "/api/unsubscribe_new",
    "/api/batch_mail/api/send",
    "/api/batch_mail/api/batch_send",
    "/api/subscribe/confirm",
    "/api/subscribe/submit",
    "/api/languages/get",
    "/already_subscribed.html",
    "/subscribe_confirm.html",
    "/subscribe_form.html",
    "/subscribe_success.html",
    "/unsubscribe_success.html",
    "/subscribe_form_code.html",
];

/// Prefixes that recipients and certificate authorities hit directly.
///
/// The Go server exempted these from the IP whitelist but *not* from the safe
/// entrance, so with a SafePath configured, open/click tracking (`/pmta/`)
/// and ACME HTTP-01 challenges answered 404. They are exempt from both here,
/// with AskAI's brand images (`/media/`, which Go kept on BillionMail's own
/// service).
pub const PUBLIC_PREFIXES: &[&str] = &["/pmta/", "/.well-known/acme-challenge/", "/media/"];

/// Paths the IP whitelist never blocks (Go's `isExcludedPath`).
pub fn whitelist_exempt(path: &str) -> bool {
    PUBLIC_EXACT_PATHS.contains(&path)
        || path.starts_with("/.well-known/acme-challenge")
        || path.starts_with("/pmta/")
        || path.starts_with("/media/")
        || path.starts_with("/roundcube")
}

/// Paths the safe entrance never blocks.
pub fn safe_entrance_exempt(path: &str) -> bool {
    PUBLIC_EXACT_PATHS.contains(&path) || PUBLIC_PREFIXES.iter().any(|p| path.starts_with(p))
}

/// Normalises a configured SafePath value (Go strips one leading `/`).
pub fn normalize_safe_path(value: &str) -> &str {
    let value = value.trim();
    value.strip_prefix('/').unwrap_or(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_path_normalisation_matches_go() {
        assert_eq!(normalize_base_path(""), "");
        assert_eq!(normalize_base_path("/"), "");
        assert_eq!(normalize_base_path("billionmail"), "/billionmail");
        assert_eq!(normalize_base_path("/billionmail/"), "/billionmail");
        assert_eq!(normalize_base_path(" /a/b/ "), "/a/b");
        assert_eq!(normalize_base_path("/a/../b"), "");
        assert_eq!(normalize_base_path("/a//b"), "");
        assert_eq!(normalize_base_path("a\\b"), "");
    }

    #[test]
    fn strips_base_path() {
        assert_eq!(strip_base_path("", "/api/x"), None);
        assert_eq!(strip_base_path("/bm", "/bm"), Some("/"));
        assert_eq!(strip_base_path("/bm", "/bm/api/x"), Some("/api/x"));
        assert_eq!(strip_base_path("/bm", "/bmx/api"), None);
        assert_eq!(strip_base_path("/bm", "/other"), None);
    }

    #[test]
    fn public_paths() {
        assert!(safe_entrance_exempt("/pmta/open/abc"));
        assert!(safe_entrance_exempt("/api/unsubscribe"));
        assert!(!safe_entrance_exempt("/api/tags/list"));
        assert!(!safe_entrance_exempt("/roundcube/"));
        assert!(whitelist_exempt("/roundcube/?_task=mail"));
        assert!(!whitelist_exempt("/api/tags/list"));
    }

    #[test]
    fn safe_path_value() {
        assert_eq!(normalize_safe_path("/abc123"), "abc123");
        assert_eq!(normalize_safe_path("abc123"), "abc123");
        assert_eq!(normalize_safe_path(""), "");
    }
}
