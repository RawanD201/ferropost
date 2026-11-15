//! Contact groups (`bm_contact_groups`).

use serde::Serialize;

/// A group with its subscription settings. JSON names follow Go's
/// `v1.ContactGroup`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "sqlx", derive(sqlx::FromRow))]
pub struct ContactGroup {
    pub id: i32,
    pub name: String,
    pub description: String,
    pub create_time: i32,
    pub update_time: i32,
    pub token: String,
    pub double_optin: i16,
    #[serde(rename = "welcome_mail_html")]
    pub welcome_mail_html: String,
    pub welcome_mail_drag: String,
    pub welcome_subject: String,
    pub send_welcome_email: i16,
    pub confirm_subject: String,
    pub confirm_mail_html: String,
    pub confirm_mail_drag: String,
    pub success_url: String,
    pub confirm_url: String,
    pub already_url: String,
    pub subscribe_form: String,
    pub unsubscribe_mail_html: String,
    pub unsubscribe_mail_drag: String,
    pub unsubscribe_subject: String,
    pub unsubscribe_redirect_url: String,
    pub send_unsubscribe_email: i16,
}

/// A row of the paged group list (Go's `v1.ContactGroupInfo`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "sqlx", derive(sqlx::FromRow))]
pub struct GroupListItem {
    #[serde(flatten)]
    #[cfg_attr(feature = "sqlx", sqlx(flatten))]
    pub group: ContactGroup,
    pub total_count: i64,
    pub active_count: i64,
    pub unsubscribe_count: i64,
    /// Filled by `group/info` only; empty in lists, as in Go.
    pub subscribe_link: String,
    pub sender: String,
}

/// The short form `/contact/group/all` returns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "sqlx", derive(sqlx::FromRow))]
pub struct GroupBrief {
    pub id: i32,
    pub name: String,
    pub description: String,
    pub create_time: i32,
    pub update_time: i32,
}

/// How `tag_contact_count` combines tags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TagLogic {
    /// Contacts with every tag.
    All,
    /// Contacts with any of the tags.
    Any,
    /// Contacts with none of the tags.
    None,
}

impl TagLogic {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "AND" => Some(Self::All),
            "OR" => Some(Self::Any),
            "NOT" => Some(Self::None),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tag_logic() {
        assert_eq!(TagLogic::parse("AND"), Some(TagLogic::All));
        assert_eq!(TagLogic::parse("NOT"), Some(TagLogic::None));
        assert_eq!(TagLogic::parse("and"), None);
    }
}
