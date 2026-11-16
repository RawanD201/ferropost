//! AskAI (Go: `service/askai`): AI providers and models (`suppliers`).
//!
//! Everything stays in Go's files under `conf/`, so nothing is lost when
//! switching cores, but nothing leaves this server for BillionMail's own
//! service (`cdn.billionmail.com`) any more.

pub mod suppliers;

/// Writes a private file (owner-only, through a temporary file), making
/// its folder owner-only too. Go wrote these files and folders 0777.
pub(crate) fn write_private(path: &std::path::Path, content: &[u8]) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }
    crate::fsio::write_atomic(path, content, 0o600)
}
