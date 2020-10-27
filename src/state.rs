use std::{
    convert::TryInto,
    fs::File,
    io::{self, Write},
    mem,
    ops::Range,
    u64,
};

use log::debug;

use crate::file::{read_all_at, write_all_at};

// The state file format is a 516-byte block as described below. It stores two
// fixed-size arrays containing the list of remaining ranges to be downloaded.
// Each write of the current state will flip between the two arrays.
//
// State block:
// | Offset | Size | Description                 |
// |--------|------|-----------------------------|
// | 0      | 1    | Version field (currently 1) |
// | 1      | 1    | Parity                      |
// | 2      | 257  | Ranges block 1 (parity 0)   |
// | 259    | 257  | Ranges block 2 (parity 1)   |
//
// Ranges block:
// | Offset | Size | Description                              |
// |--------|------|------------------------------------------|
// | 0      | 1    | Number of range pair slots used (max 16) |
// | 1      | 8    | Range 1 beginning (big endian)           |
// | 9      | 8    | Range 1 end (big endian)                 |
// | ...    | ...  | ...                                      |
// | 241    | 8    | Range 16 beginning (big endian)          |
// | 249    | 8    | Range 16 end (big endian)                |

/// Maximum number of download ranges that can be stored in the state file.
pub const MAX_RANGES: usize = 16;

const CURRENT_VERSION: u8 = 1;

const RANGES_BLOCK_SIZE: u64 =
    mem::size_of::<u8>() as u64 // Number of elements used
    + MAX_RANGES as u64         // Max elements
        * 2                     // (start, end) pair
        * mem::size_of::<u64>() as u64;

const VERSION_OFFSET: u64 = 0;
const VERSION_SIZE: u64 = mem::size_of::<u8>() as u64;

const PARITY_OFFSET: u64 = VERSION_OFFSET + VERSION_SIZE;
const PARITY_SIZE: u64 = mem::size_of::<u8>() as u64;

const STATE1_OFFSET: u64 = PARITY_OFFSET + PARITY_SIZE;
const STATE1_SIZE: u64 = RANGES_BLOCK_SIZE;

const STATE2_OFFSET: u64 = STATE1_OFFSET + STATE1_SIZE;
const STATE2_SIZE: u64 = RANGES_BLOCK_SIZE;

const STATE_BLOCK_SIZE: u64 = STATE2_OFFSET + STATE2_SIZE;

pub struct StateFile {
    file: File,
    offset: u64,
    parity_bit: bool,
    invalid: bool,
}

impl StateFile {
    /// Create a new state file handle for the given file and offset. If there
    /// is currently no state state block at the offset, an invalid state block
    /// will be written.
    pub fn new(file: File, offset: u64) -> io::Result<Self> {
        let mut s = Self {
            file,
            offset,
            parity_bit: true, // Write to ranges block 1 by default
            invalid: false,
        };

        s.initialize()?;

        Ok(s)
    }

    /// Initialize the state block. If there is no state block, then an invalid
    /// one consisting of all 0xff bytes is written.
    fn initialize(&mut self) -> io::Result<()> {
        let mut buf = [0xffu8; STATE_BLOCK_SIZE as usize];

        match read_all_at(&mut self.file, &mut buf, self.offset) {
            Ok(_) => {
                if buf[VERSION_OFFSET as usize] == 0xff {
                    debug!("Initial state block is invalid");
                    self.invalid = true;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                debug!("Writing invalid initial state block");

                write_all_at(&mut self.file, &buf, self.offset)?;
                self.file.flush()?;

                self.invalid = true;
            }
            Err(e) => return Err(e),
        }

        Ok(())
    }

    /// Return whether the state block is valid. A state block is valid for
    /// a file where [`write_state`] has successfully run once in the past.
    pub fn is_valid(&self) -> bool {
        !self.invalid
    }

    /// Read the ranges block at the specified relative offset.
    fn read_ranges_block(&mut self, block_offset: u64) -> io::Result<Vec<Range<u64>>> {
        let mut buf = [0u8; RANGES_BLOCK_SIZE as usize];
        let mut pos = 0;

        read_all_at(&mut self.file, &mut buf, self.offset + block_offset)?;

        let size = buf[pos] as usize;
        pos += 1;

        if size > MAX_RANGES {
            return Err(io::Error::new(io::ErrorKind::InvalidData,
                format!("Too many ranges: {}", size)));
        }

        let mut result = Vec::new();

        for _ in 0..size {
            let start = u64::from_be_bytes(buf[pos..pos + 8].try_into().unwrap());
            pos += 8;
            let end = u64::from_be_bytes(buf[pos..pos + 8].try_into().unwrap());
            pos += 8;

            result.push(start..end);
        }

        debug!("Validating ranges block data: {:?}", result);

        result.sort_by_key(|r| r.start);
        result.retain(|r| r.end - r.start > 0);

        let is_increasing = |w: &[Range<u64>]| {
            w[0].start <= w[0].end
            && w[0].end <= w[1].start
            && w[1].start <= w[1].end
            && w[1].end <= self.offset
        };

        if !result.windows(2).all(is_increasing) {
            debug!("Ranges overlap or are not increasing: {:?}", result);

            return Err(io::Error::new(io::ErrorKind::InvalidData,
                "Ranges overlap or are not increasing"));
        }

        Ok(result)
    }

    /// Write the specified ranges to the ranges block at the specified relative
    /// offset.
    fn write_ranges_block(&mut self, ranges: &[Range<u64>], block_offset: u64) -> io::Result<()> {
        assert!(ranges.len() <= MAX_RANGES);

        let mut input = ranges.to_owned();
        input.sort_by_key(|r| r.start);
        input.retain(|r| r.end - r.start > 0);

        let mut buf = [0u8; RANGES_BLOCK_SIZE as usize];
        let mut pos = 0;
        buf[pos] = input.len() as u8;
        pos += 1;

        for r in input {
            buf[pos..pos + 8].copy_from_slice(&r.start.to_be_bytes());
            pos += 8;
            buf[pos..pos + 8].copy_from_slice(&r.end.to_be_bytes());
            pos += 8;
        }

        write_all_at(&mut self.file, &buf, self.offset + block_offset)
    }

    /// Read the current state from the file. This will read one of the two
    /// states based on the last successfully written parity.
    pub fn read_state(&mut self) -> io::Result<Vec<Range<u64>>> {
        let mut version = [0u8; 1];
        read_all_at(
            &mut self.file,
            &mut version,
            self.offset + VERSION_OFFSET,
        )?;

        if version[0] != CURRENT_VERSION {
            return Err(io::Error::new(io::ErrorKind::InvalidData,
                format!("Unrecognized state version: {}", version[0])));
        }

        let mut parity = [0u8; 1];
        read_all_at(
            &mut self.file,
            &mut parity,
            self.offset + PARITY_OFFSET,
        )?;

        let new_parity = parity[0] != 0;

        let block_offset = if new_parity { STATE2_OFFSET } else { STATE1_OFFSET };
        let ranges = self.read_ranges_block(block_offset)?;

        debug!("Read ranges for parity {}: {:?}", new_parity as u8, ranges);

        self.parity_bit = new_parity;
        self.invalid = false;

        Ok(ranges)
    }

    /// Write the given state to the file. This will write the new state to the
    /// opposite parity block of the previous state. The previous state block is
    /// never overwritten to reduce the chance of an unclean shutdown corrupting
    /// the file.
    pub fn write_state(&mut self, ranges: &[Range<u64>]) -> io::Result<()> {
        let new_parity = !self.parity_bit;

        debug!("Writing ranges for parity {}: {:?}", new_parity as u8, ranges);

        write_all_at(
            &mut self.file,
            &[CURRENT_VERSION],
            self.offset + VERSION_OFFSET,
        )?;
        self.file.flush()?;

        let block_offset = if new_parity { STATE2_OFFSET } else { STATE1_OFFSET };
        self.write_ranges_block(ranges, block_offset)?;
        self.file.flush()?;

        write_all_at(
            &mut self.file,
            &[new_parity as u8],
            self.offset + PARITY_OFFSET,
        )?;
        self.file.flush()?;

        self.parity_bit = new_parity;
        self.invalid = false;

        Ok(())
    }
}
