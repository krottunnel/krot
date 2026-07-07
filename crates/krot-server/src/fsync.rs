//! Parent-directory fsync after atomic rename.
//!
//! `File::sync_all` on the tmp file guarantees the file **data** is on
//! stable storage, but on POSIX the rename that publishes it can still be
//! lost across a crash — the directory's inode-link update lives in the
//! directory's own on-disk representation. Calling `sync_all` on a handle
//! to the parent directory forces that update to disk too, giving us the
//! full crash-consistency envelope spec §13 asks for.

use std::path::Path;

/// Sync the directory containing `child` so a preceding rename is durable.
///
/// No-op on non-Unix targets (Windows semantics differ; `File::sync_all` on
/// the renamed file is usually enough there).
pub fn sync_parent(child: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        let parent = child.parent().unwrap_or(Path::new("."));
        let file = std::fs::File::open(parent)?;
        file.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        let _ = child;
    }
    Ok(())
}
