use std::fs;
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

pub fn ensure_parent_dir(path: &str) -> std::io::Result<()> {
    if let Some(parent) = Path::new(path).parent() {
        fs::create_dir_all(parent)?;
    }
    Ok(())
}

pub fn write_private_file_atomic(path: &str, data: &[u8]) -> std::io::Result<()> {
    ensure_parent_dir(path)?;
    let tmp = format!("{path}.tmp");

    #[cfg(unix)]
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        use std::io::Write;
        f.write_all(data)?;
        f.sync_all()?;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;
    }

    #[cfg(not(unix))]
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)?;
        use std::io::Write;
        f.write_all(data)?;
        f.sync_all()?;
    }

    fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(unix)]
pub fn verify_private_file_permissions(path: &str) -> std::io::Result<()> {
    if std::env::var("ZK_ARCHE_SKIP_PERM_CHECK").ok().as_deref() == Some("1") {
        return Ok(());
    }

    let mode = std::fs::metadata(path)?.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("{path} must not be group/world accessible (mode {:o})", mode),
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
pub fn verify_private_file_permissions(_path: &str) -> std::io::Result<()> {
    Ok(())
}
