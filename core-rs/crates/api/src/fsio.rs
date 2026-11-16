//! Writing files other processes read while they change.

use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

/// Writes `content` to a temporary file next to `path` with `mode`, then
/// renames it over `path`, so readers see the old or the new file, never
/// half of one, and a secret is never readable by others in between.
pub fn write_atomic(path: &Path, content: &[u8], mode: u32) -> io::Result<()> {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let tmp = path.with_file_name(format!(".{name}.{}.tmp", std::process::id()));
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .open(&tmp)?;
        // `mode` is masked by the umask on creation; set it exactly.
        file.set_permissions(std::fs::Permissions::from_mode(mode))?;
        file.write_all(content)?;
        file.sync_all()?;
        std::fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_with_mode() {
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join("key.pem");
        std::fs::write(&path, "old").expect("old");
        write_atomic(&path, b"new", 0o600).expect("write");
        assert_eq!(std::fs::read_to_string(&path).expect("read"), "new");
        let mode = std::fs::metadata(&path).expect("meta").permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        assert_eq!(
            std::fs::read_dir(dir.path()).expect("ls").count(),
            1,
            "no temp left"
        );
    }
}
