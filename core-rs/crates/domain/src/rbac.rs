//! Mapping from API paths to the `(module, action, resource)` triple stored in
//! the `permission` table.
//!
//! This is a faithful port of `PathToRouteInfo` in
//! `core/internal/service/middlewares/rbac.go`: permissions already granted in
//! the database must keep meaning the same thing after a route moves to Rust.

/// Modules known to RBAC. Order matters: the first module whose name appears
/// as a path segment wins, exactly like the Go implementation.
pub const MODULES: &[&str] = &[
    "account",
    "role",
    "permission",
    "domains",
    "mail_boxes",
    "overview",
    "dockerapi",
    "contact",
    "email_template",
    "batch_mail",
    "files",
    "abnormal_recipient",
    "languages",
    "mail_services",
    "relay",
    "settings",
    "subscribe_list",
    "operation_log",
    "askai",
    "tags",
];

/// Role name that bypasses every permission check.
pub const ADMIN_ROLE: &str = "admin";

#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct RouteInfo {
    pub module: String,
    pub action: String,
    pub resource: String,
}

impl RouteInfo {
    /// Go denies access when any component could not be derived.
    pub fn is_complete(&self) -> bool {
        !self.module.is_empty() && !self.action.is_empty() && !self.resource.is_empty()
    }
}

/// Derives the permission triple for an API path.
pub fn route_info(path: &str) -> RouteInfo {
    let module = MODULES
        .iter()
        .find(|m| path.contains(&format!("/{m}/")) || path.ends_with(&format!("/{m}")))
        .map(|m| (*m).to_owned())
        .unwrap_or_default();

    let (resource, action) = match api_segments(path) {
        Some((resource, action)) => (resource.to_owned(), crud_action(action).to_owned()),
        None => (String::new(), String::new()),
    };

    RouteInfo {
        module,
        action,
        resource,
    }
}

/// Equivalent of the unanchored Go regex `/api/(\w+)/(\w+)(?:/.*)?`:
/// returns the first `(resource, action)` pair found in the path.
fn api_segments(path: &str) -> Option<(&str, &str)> {
    const PREFIX: &str = "/api/";
    let is_word = |b: &u8| b.is_ascii_alphanumeric() || *b == b'_';

    let mut from = 0;
    while let Some(offset) = path[from..].find(PREFIX) {
        let start = from + offset;
        from = start + 1;

        let rest = &path[start + PREFIX.len()..];
        let first_len = rest.bytes().take_while(is_word).count();
        if first_len == 0 || rest.as_bytes().get(first_len) != Some(&b'/') {
            continue;
        }

        let tail = &rest[first_len + 1..];
        let second_len = tail.bytes().take_while(is_word).count();
        if second_len == 0 {
            continue;
        }

        return Some((&rest[..first_len], &tail[..second_len]));
    }

    None
}

fn crud_action(action: &str) -> &str {
    match action {
        "list" | "detail" => "read",
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Same table as core/internal/service/middlewares/rbac_test.go.
    #[test]
    fn matches_go_path_to_route_info() {
        let cases: &[(&str, &str, &str, &str)] = &[
            ("/api/domains/list", "domains", "read", "domains"),
            ("/api/domains/detail/1", "domains", "read", "domains"),
            ("/api/domains/create", "domains", "create", "domains"),
            ("/api/domains/update", "domains", "update", "domains"),
            ("/api/domains/delete", "domains", "delete", "domains"),
            ("/api/account/list", "account", "read", "account"),
            ("/api/role/list", "role", "read", "role"),
            ("/api/permission/list", "permission", "read", "permission"),
            ("/api/mail_boxes/list", "mail_boxes", "read", "mail_boxes"),
            ("/api/overview/list", "overview", "read", "overview"),
            ("/api/dockerapi/list", "dockerapi", "read", "dockerapi"),
            ("/api/contact/list", "contact", "read", "contact"),
            (
                "/api/email_template/list",
                "email_template",
                "read",
                "email_template",
            ),
            ("/api/batch_mail/list", "batch_mail", "read", "batch_mail"),
            ("/api/files/list", "files", "read", "files"),
            (
                "/api/abnormal_recipient/list",
                "abnormal_recipient",
                "read",
                "abnormal_recipient",
            ),
            ("/api/languages/list", "languages", "read", "languages"),
            (
                "/api/mail_services/list",
                "mail_services",
                "read",
                "mail_services",
            ),
            ("/api/relay/list", "relay", "read", "relay"),
            ("/api/settings/list", "settings", "read", "settings"),
            (
                "/api/subscribe_list/list",
                "subscribe_list",
                "read",
                "subscribe_list",
            ),
            (
                "/api/operation_log/list",
                "operation_log",
                "read",
                "operation_log",
            ),
            ("/api/askai/list", "askai", "read", "askai"),
            ("/api/tags/list", "tags", "read", "tags"),
            ("/api/domains/sync", "domains", "sync", "domains"),
            ("/api/relay/test", "relay", "test", "relay"),
            ("", "", "", ""),
            ("/", "", "", ""),
            ("/api/unknown/list", "", "read", "unknown"),
            ("/api/domains", "domains", "", ""),
            (
                "/api/batch_mail/something/extra",
                "batch_mail",
                "something",
                "batch_mail",
            ),
        ];

        for (path, module, action, resource) in cases {
            let got = route_info(path);
            assert_eq!(got.module, *module, "module for {path:?}");
            assert_eq!(got.action, *action, "action for {path:?}");
            assert_eq!(got.resource, *resource, "resource for {path:?}");
        }
    }

    #[test]
    fn skips_non_matching_prefix_and_keeps_searching() {
        let got = route_info("/api//api/tags/all");
        assert_eq!(
            (got.resource.as_str(), got.action.as_str()),
            ("tags", "all")
        );
    }

    #[test]
    fn completeness() {
        assert!(route_info("/api/tags/list").is_complete());
        assert!(!route_info("/api/unknown/list").is_complete());
        assert!(!route_info("/api/domains").is_complete());
    }
}
