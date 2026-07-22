use super::*;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::ffi::{CStr, CString};
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;

use rand::rngs::OsRng;
use rand::RngCore;

#[cfg(not(unix))]
fn validate_regular_destination(path: &Path) -> Result<(), IdentityError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(IdentityError::UnsafePath(
            format!("{} is a symbolic link", path.display()),
        )),
        Ok(metadata) if !metadata.file_type().is_file() => Err(IdentityError::UnsafePath(format!(
            "{} is not a regular file",
            path.display()
        ))),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

#[cfg(not(unix))]
fn checked_parent(path: &Path) -> Result<&Path, IdentityError> {
    let parent = path
        .parent()
        .filter(|candidate| !candidate.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let metadata = std::fs::symlink_metadata(parent)?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(IdentityError::UnsafePath(format!(
            "{} is not a direct regular directory",
            parent.display()
        )));
    }
    Ok(parent)
}

#[cfg(unix)]
pub(crate) struct OpenedParent {
    fd: OwnedFd,
    path: PathBuf,
}

#[cfg(unix)]
pub(crate) fn open_parent_and_name(path: &Path) -> Result<(OpenedParent, CString), IdentityError> {
    let parent_path = path
        .parent()
        .filter(|candidate| !candidate.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .ok_or_else(|| IdentityError::UnsafePath(format!("{} has no file name", path.display())))?;
    let file_name = CString::new(file_name.as_bytes()).map_err(|_| {
        IdentityError::UnsafePath(format!("{} contains a NUL byte", path.display()))
    })?;
    let parent_c = CString::new(parent_path.as_os_str().as_bytes()).map_err(|_| {
        IdentityError::UnsafePath(format!("{} contains a NUL byte", parent_path.display()))
    })?;

    let raw_fd = unsafe {
        libc::open(
            parent_c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if raw_fd < 0 {
        return Err(path_syscall_error(
            std::io::Error::last_os_error(),
            parent_path,
        ));
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
    let parent = OpenedParent {
        fd,
        path: parent_path.to_path_buf(),
    };
    let metadata = stat_fd(parent.fd.as_raw_fd())?;
    validate_parent_stat(&metadata, &parent.path)?;
    Ok((parent, file_name))
}

#[cfg(unix)]
fn stat_fd(fd: libc::c_int) -> Result<libc::stat, IdentityError> {
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(fd, metadata.as_mut_ptr()) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(unsafe { metadata.assume_init() })
}

#[cfg(unix)]
fn stat_at(parent: &OpenedParent, name: &CStr) -> Result<Option<libc::stat>, IdentityError> {
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    let result = unsafe {
        libc::fstatat(
            parent.fd.as_raw_fd(),
            name.as_ptr(),
            metadata.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result == 0 {
        return Ok(Some(unsafe { metadata.assume_init() }));
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ENOENT) {
        return Ok(None);
    }
    Err(path_syscall_error(error, &parent.path))
}

#[cfg(unix)]
fn validate_parent_stat(metadata: &libc::stat, parent: &Path) -> Result<(), IdentityError> {
    if metadata.st_mode & libc::S_IFMT != libc::S_IFDIR {
        return Err(IdentityError::UnsafePath(format!(
            "{} is not a directory",
            parent.display()
        )));
    }
    if metadata.st_uid != unsafe { libc::geteuid() } {
        return Err(IdentityError::UnsafePath(format!(
            "{} is not owned by the effective user",
            parent.display()
        )));
    }
    if metadata.st_mode & 0o022 != 0 {
        return Err(IdentityError::UnsafePath(format!(
            "{} is group- or other-writable",
            parent.display()
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn validate_identity_stat(metadata: &libc::stat, path: &Path) -> Result<(), IdentityError> {
    if metadata.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Err(IdentityError::UnsafePath(format!(
            "{} is not a regular file",
            path.display()
        )));
    }
    if metadata.st_uid != unsafe { libc::geteuid() } {
        return Err(IdentityError::UnsafePath(format!(
            "{} is not owned by the effective user",
            path.display()
        )));
    }
    if metadata.st_mode & 0o077 != 0 {
        return Err(IdentityError::UnsafePath(format!(
            "{} grants group or other permissions",
            path.display()
        )));
    }
    if metadata.st_nlink != 1 {
        return Err(IdentityError::UnsafePath(format!(
            "{} must have exactly one hard link",
            path.display()
        )));
    }
    if metadata.st_size < 0 || metadata.st_size as u64 > MAX_IDENTITY_FILE_BYTES {
        return Err(IdentityError::IdentityFileTooLarge);
    }
    Ok(())
}

#[cfg(unix)]
fn validate_existing_identity(
    parent: &OpenedParent,
    name: &CStr,
    path: &Path,
) -> Result<(), IdentityError> {
    if let Some(metadata) = stat_at(parent, name)? {
        validate_identity_stat(&metadata, path)?;
    }
    Ok(())
}

#[cfg(unix)]
fn create_temporary_file(parent: &OpenedParent) -> Result<(CString, std::fs::File), IdentityError> {
    for _ in 0..8 {
        let mut nonce = [0_u8; 16];
        OsRng.fill_bytes(&mut nonce);
        let name = CString::new(format!(".sovereign-identity.{}.tmp", hex::encode(nonce)))
            .expect("temporary name contains only ASCII");
        let raw_fd = unsafe {
            libc::openat(
                parent.fd.as_raw_fd(),
                name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if raw_fd >= 0 {
            let file = unsafe { std::fs::File::from_raw_fd(raw_fd) };
            if unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } < 0 {
                let error = std::io::Error::last_os_error();
                drop(file);
                let _ = unlink_at(parent, &name);
                return Err(error.into());
            }
            return Ok((name, file));
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::AlreadyExists {
            return Err(path_syscall_error(error, &parent.path));
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "could not allocate a unique identity temporary file",
    )
    .into())
}

#[cfg(unix)]
fn unlink_at(parent: &OpenedParent, name: &CStr) -> Result<(), IdentityError> {
    if unsafe { libc::unlinkat(parent.fd.as_raw_fd(), name.as_ptr(), 0) } < 0 {
        return Err(path_syscall_error(
            std::io::Error::last_os_error(),
            &parent.path,
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn rename_at(
    parent: &OpenedParent,
    source: &CStr,
    destination: &CStr,
) -> Result<(), IdentityError> {
    if unsafe {
        libc::renameat(
            parent.fd.as_raw_fd(),
            source.as_ptr(),
            parent.fd.as_raw_fd(),
            destination.as_ptr(),
        )
    } < 0
    {
        return Err(path_syscall_error(
            std::io::Error::last_os_error(),
            &parent.path,
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn sync_parent(parent: &OpenedParent) -> Result<(), IdentityError> {
    if unsafe { libc::fsync(parent.fd.as_raw_fd()) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

#[cfg(unix)]
fn path_syscall_error(error: std::io::Error, path: &Path) -> IdentityError {
    if matches!(error.raw_os_error(), Some(libc::ELOOP | libc::ENOTDIR)) {
        IdentityError::UnsafePath(format!(
            "{} contains a symbolic link or non-directory component",
            path.display()
        ))
    } else {
        IdentityError::Io(error)
    }
}

#[cfg(unix)]
pub(crate) fn atomic_write_private(path: &Path, bytes: &[u8]) -> Result<(), IdentityError> {
    if bytes.len() as u64 > MAX_IDENTITY_FILE_BYTES {
        return Err(IdentityError::IdentityFileTooLarge);
    }
    let (parent, name) = open_parent_and_name(path)?;
    atomic_write_private_at(&parent, &name, path, bytes)
}

#[cfg(unix)]
pub(crate) fn atomic_write_private_at(
    parent: &OpenedParent,
    name: &CStr,
    path: &Path,
    bytes: &[u8],
) -> Result<(), IdentityError> {
    if bytes.len() as u64 > MAX_IDENTITY_FILE_BYTES {
        return Err(IdentityError::IdentityFileTooLarge);
    }
    validate_existing_identity(parent, name, path)?;
    let (temporary_name, mut file) = create_temporary_file(parent)?;
    let mut renamed = false;
    let result = (|| -> Result<(), IdentityError> {
        file.write_all(bytes)?;
        file.sync_all()?;
        let temporary_stat = stat_fd(file.as_raw_fd())?;
        validate_identity_stat(&temporary_stat, path)?;
        if temporary_stat.st_mode & 0o777 != 0o600 {
            return Err(IdentityError::UnsafePath(
                "temporary identity file does not have mode 0600".into(),
            ));
        }
        drop(file);

        // The parent directory is a stable descriptor owned by the effective
        // user and is not writable by other users. Re-check the destination
        // entry immediately before replacing it within that same directory.
        validate_existing_identity(parent, name, path)?;
        rename_at(parent, &temporary_name, name)?;
        renamed = true;
        let installed = stat_at(parent, name)?.ok_or_else(|| {
            IdentityError::UnsafePath(format!("{} disappeared after rename", path.display()))
        })?;
        validate_identity_stat(&installed, path)?;
        if installed.st_mode & 0o777 != 0o600 {
            return Err(IdentityError::UnsafePath(format!(
                "{} was not installed with mode 0600",
                path.display()
            )));
        }
        sync_parent(parent)
    })();
    if result.is_err() && !renamed {
        let _ = unlink_at(parent, &temporary_name);
    }
    result
}

#[cfg(not(unix))]
pub(crate) fn atomic_write_private(path: &Path, bytes: &[u8]) -> Result<(), IdentityError> {
    // Non-Unix platforms do not provide the dirfd and ownership guarantees of
    // the Unix implementation. Callers must protect the parent directory.
    validate_regular_destination(path)?;
    let _ = checked_parent(path)?;
    std::fs::write(path, bytes)?;
    Ok(())
}

#[cfg(unix)]
pub(crate) fn read_regular_file(path: &Path) -> Result<Vec<u8>, IdentityError> {
    let (parent, name) = open_parent_and_name(path)?;
    let pre_open = stat_at(&parent, &name)?.ok_or_else(|| {
        IdentityError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("{} does not exist", path.display()),
        ))
    })?;
    validate_identity_stat(&pre_open, path)?;

    let raw_fd = unsafe {
        libc::openat(
            parent.fd.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0,
        )
    };
    if raw_fd < 0 {
        return Err(path_syscall_error(std::io::Error::last_os_error(), path));
    }
    let mut file = unsafe { std::fs::File::from_raw_fd(raw_fd) };
    let metadata = stat_fd(file.as_raw_fd())?;
    validate_identity_stat(&metadata, path)?;
    let mut bytes = Vec::with_capacity(metadata.st_size as usize);
    Read::by_ref(&mut file)
        .take(MAX_IDENTITY_FILE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_IDENTITY_FILE_BYTES {
        return Err(IdentityError::IdentityFileTooLarge);
    }
    Ok(bytes)
}

#[cfg(not(unix))]
pub(crate) fn read_regular_file(path: &Path) -> Result<Vec<u8>, IdentityError> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(IdentityError::UnsafePath(format!(
            "{} is not a regular file",
            path.display()
        )));
    }
    if metadata.len() > MAX_IDENTITY_FILE_BYTES {
        return Err(IdentityError::IdentityFileTooLarge);
    }
    Ok(std::fs::read(path)?)
}
