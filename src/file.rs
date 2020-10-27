use std::{
    fs::File,
    io,
    path::Path,
};

use log::trace;

/// Read data from offset. The file position *will* be changed.
#[cfg(windows)]
pub fn read_at(file: &mut File, buf: &mut [u8], offset: u64) -> io::Result<usize> {
    use std::os::windows::fs::FileExt;
    file.seek_read(buf, offset)
}

/// Read data from offset. The file position will *not* be changed.
#[cfg(unix)]
pub fn read_at(file: &mut File, buf: &mut [u8], offset: u64) -> io::Result<usize> {
    use std::os::unix::fs::FileExt;
    file.read_at(buf, offset)
}

/// Read a byte slice of the given size at the specified offset. The file
/// position may be changed depending on the OS. The EOF is reached before the
/// reads are complete, [`std::io::ErrorKind::UnexpectedEof`] is returned.
pub fn read_all_at(file: &mut File, mut buf: &mut [u8], mut offset: u64) -> io::Result<()> {
    trace!("Reading {} bytes at offset {}", buf.len(), offset);

    while !buf.is_empty() {
        let n = read_at(file, buf, offset)?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }

        buf = &mut buf[n..];
        offset += n as u64;
    }

    Ok(())
}

/// Write data to offset. The file position *will* be changed.
#[cfg(windows)]
pub fn write_at(file: &mut File, buf: &[u8], offset: u64) -> io::Result<usize> {
    use std::os::windows::fs::FileExt;
    file.seek_write(buf, offset)
}

/// Write data to offset. The file position will *not* be changed.
#[cfg(unix)]
pub fn write_at(file: &mut File, buf: &[u8], offset: u64) -> io::Result<usize> {
    use std::os::unix::fs::FileExt;
    file.write_at(buf, offset)
}

/// Write all of the specified data to the specified offset. The file position
/// may be changed depending on the OS. The EOF is reached before the writes are
/// complete, [`std::io::ErrorKind::UnexpectedEof`] is returned.
pub fn write_all_at(file: &mut File, mut buf: &[u8], mut offset: u64) -> io::Result<()> {
    trace!("Writing {} bytes at offset {}", buf.len(), offset);

    while !buf.is_empty() {
        let n = write_at(file, buf, offset)?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }

        buf = &buf[n..];
        offset += n as u64;
    }

    Ok(())
}

/// Rename a file with POSIX semantics (atomic and overwrites destination if it
/// exists). This uses `FILE_RENAME_FLAG_POSIX_SEMANTICS` and requires Windows
/// 10 1607 or newer.
#[cfg(windows)]
pub fn rename_atomic(src: &Path, dest: &Path) -> io::Result<()> {
    use std::{
        fs::OpenOptions,
        iter,
        mem,
        os::windows::{
            ffi::OsStrExt,
            fs::OpenOptionsExt,
            io::AsRawHandle,
        },
        ptr,
    };
    use memoffset::offset_of;
    use winapi::{
        shared::minwindef::{BOOL, DWORD},
        um::{
            fileapi::{FILE_RENAME_INFO, SetFileInformationByHandle},
            minwinbase::FileRenameInfoEx,
            winnt::DELETE,
        },
    };

    // The winapi crate doesn't have these constants
    const FILE_RENAME_FLAG_REPLACE_IF_EXISTS: DWORD = 0x00000001;
    const FILE_RENAME_FLAG_POSIX_SEMANTICS: DWORD = 0x00000002;

    let file = OpenOptions::new()
        .access_mode(DELETE)
        .open(src)?;

    let struct_size_wchars = mem::size_of::<FILE_RENAME_INFO>() / 2;
    let base_size_wchars = offset_of!(FILE_RENAME_INFO, FileName) / 2;
    let mut buf: Vec<u16> = iter::repeat(0u16)
        .take(base_size_wchars)
        .chain(dest.as_os_str().encode_wide())
        .chain(iter::once(0))
        .collect();

    // Make sure the filename contains no embedded \u0000
    if buf[base_size_wchars..buf.len() - 1].contains(&0) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput,
            "Destination filename contains \\u{0000}"));
    }

    // No NULL-terminator
    let filename_wchars = buf.len() - base_size_wchars - 1;

    // If the filename is short, buf might be smaller than
    // sizeof(FILE_RENAME_INFO)
    if buf.len() < struct_size_wchars {
        buf.resize(struct_size_wchars, 0);
    }

    unsafe {
        let info = buf.as_mut_ptr() as *mut FILE_RENAME_INFO;
        // Actually is a union with 'flags' field. 'flags' is used with
        // FileRenameInfoEx
        (*info).ReplaceIfExists = (FILE_RENAME_FLAG_REPLACE_IF_EXISTS
            | FILE_RENAME_FLAG_POSIX_SEMANTICS) as BOOL;
        (*info).RootDirectory = ptr::null_mut();
        // This appears to be unused. SetFileInformationByHandle reads the
        // FileName field until it hits a NULL-terminator.
        (*info).FileNameLength = filename_wchars as DWORD;

        let ret = SetFileInformationByHandle(
            file.as_raw_handle(),
            FileRenameInfoEx,
            buf.as_mut_ptr() as *mut _ as *mut _,
            buf.len() as DWORD * 2, // byte size
        );

        if ret == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

/// Rename a file with POSIX semantics (atomic and overwrites destination if it
/// exists). This just calls [`std::fs::rename`] on Unix-like platforms.
#[cfg(unix)]
pub fn rename_atomic(src: &Path, dest: &Path) -> io::Result<()> {
    std::fs::rename(src, dest)
}
