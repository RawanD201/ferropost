//! Built-in mail templates and subscription defaults (Go:
//! `subscribe_list.GetDefaultTemplate`, `GetSubscribeFormCode`).

use crate::state::AppState;

#[derive(Debug, Clone, Copy)]
pub enum Kind {
    Welcome,
    Confirm,
    Unsubscribe,
}

impl Kind {
    fn files(self) -> (&'static str, &'static str) {
        match self {
            Self::Welcome => (
                "default_welcome_email/welcome_email",
                "<p>Welcome to subscribe!</p>",
            ),
            Self::Confirm => (
                "default_confirm_email/confirm_email",
                "<p>Please confirm your subscription.</p>",
            ),
            Self::Unsubscribe => (
                "default_unsubscribe_email/unsubscribe_email",
                "<p>You have been unsubscribed.</p>",
            ),
        }
    }
}

/// `(html, drag_data)` of a built-in mail: `<name>.html` and `<name>.txt`
/// under the template directory, or Go's fallback HTML.
pub fn default_mail(state: &AppState, kind: Kind) -> (String, String) {
    let (base, fallback) = kind.files();
    let dir = &state.config.template_dir;
    match std::fs::read_to_string(dir.join(format!("{base}.html"))) {
        Ok(html) => (
            html,
            std::fs::read_to_string(dir.join(format!("{base}.txt"))).unwrap_or_default(),
        ),
        Err(_) => (fallback.to_owned(), String::new()),
    }
}

/// Embeddable form HTML pointing at the group's submit URL.
pub fn subscribe_form_code(state: &AppState, host: &str, group_token: &str) -> String {
    let content =
        std::fs::read_to_string(state.config.template_dir.join("subscribe_form_code.html"))
            .unwrap_or_default();
    if !content.contains("{{ SubmitURL . }}") {
        return String::new();
    }
    content.replace(
        "{{ SubmitURL . }}",
        &format!("{host}/api/subscribe/submit?token={group_token}"),
    )
}
