use std::{
    fs::File,
    io,
};

use log::trace;

// Write data to offset. The file position *will* be changed.
#[cfg(windows)]
pub fn write_at(file: &mut File, buf: &[u8], offset: u64) -> io::Result<usize> {
    use std::os::windows::fs::FileExt;
    file.seek_write(buf, offset)
}

// Write data to offset. The file position will *not* be changed.
#[cfg(unix)]
pub fn write_at(file: &mut File, buf: &[u8], offset: u64) -> io::Result<usize> {
    use std::os::unix::fs::FileExt;
    file.write_at(buf, offset)
}

// Write all of the specified data to the specified offset. The file position
// may be changed depending on the OS. The EOF is reached before the writes are
// complete, [`std::io::ErrorKind::UnexpectedEof`] is returned.
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

    return Ok(())
}