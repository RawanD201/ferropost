//! Operation (audit) log.

use serde::Serialize;

/// A row of `bm_operation_logs` as the log viewer receives it (Go's
/// `entity.OperationLog`). `info` is the snapshot file path, if any.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "sqlx", derive(sqlx::FromRow))]
pub struct LogEntry {
    pub id: i64,
    pub user_id: i64,
    #[serde(rename = "type")]
    #[cfg_attr(feature = "sqlx", sqlx(rename = "type"))]
    pub log_type: String,
    pub log: String,
    pub ip: String,
    pub info: String,
    pub addtime: i64,
    /// `"unknown"` when the account no longer exists.
    pub username: String,
}

/// Categories stored in `bm_operation_logs.type`. The string values are the
/// ones Go writes (`consts.LOGTYPE`), so filters in the log viewer keep
/// working across both servers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogType {
    Task,
    Template,
    SendApi,
    ContactsGroup,
    Contacts,
    Domain,
    Mailboxes,
    Smtp,
    Settings,
    Service,
    Bcc,
    MailForward,
    AbnormalRecipient,
    DockerApi,
    Language,
    Login,
    PostfixQueue,
    Tag,
}

impl LogType {
    pub const ALL: [LogType; 18] = [
        Self::Task,
        Self::Template,
        Self::SendApi,
        Self::ContactsGroup,
        Self::Contacts,
        Self::Domain,
        Self::Mailboxes,
        Self::Smtp,
        Self::Settings,
        Self::Service,
        Self::Bcc,
        Self::MailForward,
        Self::AbnormalRecipient,
        Self::DockerApi,
        Self::Language,
        Self::Login,
        Self::PostfixQueue,
        Self::Tag,
    ];

    /// Value stored in the database.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Task => "Email Marketing Task",
            Self::Template => "Email Template",
            Self::SendApi => "Send API",
            Self::ContactsGroup => "Contacts-Group",
            Self::Contacts => "Contacts-Subscribers",
            Self::Domain => "Domain",
            Self::Mailboxes => "Mailboxes",
            Self::Smtp => "SMTP Relay",
            Self::Settings => "Settings-Common",
            Self::Service => "Settings-Service",
            Self::Bcc => "Settings-BCC",
            Self::MailForward => "Settings-Mail Forward",
            Self::AbnormalRecipient => "Abnormal Recipient",
            Self::DockerApi => "Docker Api",
            Self::Language => "Language",
            Self::Login => "Login",
            Self::PostfixQueue => "Postfix Queue",
            Self::Tag => "Contacts-Tag",
        }
    }

    /// Go field name (`LOGTYPE.<Key>`), used as the key of the type list the
    /// log viewer requests.
    pub fn key(self) -> &'static str {
        match self {
            Self::Task => "Task",
            Self::Template => "Template",
            Self::SendApi => "SendAPI",
            Self::ContactsGroup => "ContactsGroup",
            Self::Contacts => "Contacts",
            Self::Domain => "Domain",
            Self::Mailboxes => "Mailboxes",
            Self::Smtp => "SMTP",
            Self::Settings => "Settings",
            Self::Service => "Service",
            Self::Bcc => "BCC",
            Self::MailForward => "MailForward",
            Self::AbnormalRecipient => "AbnormalRecipient",
            Self::DockerApi => "DockerApi",
            Self::Language => "Language",
            Self::Login => "Login",
            Self::PostfixQueue => "PostfixQueue",
            Self::Tag => "Tag",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_match_go() {
        assert_eq!(LogType::Tag.as_str(), "Contacts-Tag");
        assert_eq!(LogType::Contacts.as_str(), "Contacts-Subscribers");
        assert_eq!(LogType::SendApi.key(), "SendAPI");
        let keys: std::collections::HashSet<_> = LogType::ALL.iter().map(|t| t.key()).collect();
        assert_eq!(keys.len(), LogType::ALL.len());
    }
}
