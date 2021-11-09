#![deny(warnings, missing_docs)]
//! Library implementing the openaes standard used by the [Team Win Recovery Project (TWRP)][1], as
//! of 2018-08-24.
//!
//! There are both implementations for reading (decrypting) and writing (encrypting)
//! data. The intention is to make encrypted TWRP backups accessible or even facilitate
//! re-compression with a different/more modern algorithm.
//!
//! [1]: <https://github.com/TeamWin/Team-Win-Recovery-Project/tree/58f2132bc3954fc704787d477500a209eedb8e29/openaes>

use aes::cipher::generic_array::GenericArray;
use aes::{Aes128, BlockCipher};
pub use decrypt::RoaesSource;
pub use encrypt::RoaesSink;
use snafu::{Backtrace, GenerateBacktrace, Snafu};
use std::io::ErrorKind as IOErrorKind;

mod decrypt;
mod encrypt;
mod util;

const OAES_BLOCK_SIZE: usize = 16;
const OAES_BLOCK_SIZE64: u64 = OAES_BLOCK_SIZE as u64;
const FILE_BLOCK_SIZE: usize = 4096;
const FILE_BLOCK_SIZE64: u64 = FILE_BLOCK_SIZE as u64;

type AesBlock = GenericArray<u8, <Aes128 as BlockCipher>::BlockSize>;

/// Error type indicating errors and encapsulating errors from lower layers.
#[allow(missing_docs)]
#[derive(Debug, Snafu)]
pub enum RoaesError {
    /// No expected `OAES` magic number found in input for decryption.
    NoMagicNumber,
    /// End of file reached.
    Eof,
    /// Version, type, option or flag set to an unsupported value in the header.
    Incompatible { desc: String, backtrace: Backtrace },
    /// Error in underlying cryptography code.
    Crypto {
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
        backtrace: Backtrace,
        desc: String,
    },
    /// General error.
    General { backtrace: Backtrace, desc: String },
    /// IO error
    IO {
        source: std::io::Error,
        backtrace: Backtrace,
        desc: String,
    },
}

impl RoaesError {
    fn underflow_multiple_aes_block(read: usize) -> Self {
        RoaesError::IO {
            source: std::io::Error::new(
                IOErrorKind::UnexpectedEof,
                "did not read multiple of AES block size",
            ),
            backtrace: Backtrace::generate(),
            desc: format!(
                "did not read multiple of AES block size, read: {} byte",
                read
            ),
        }
    }

    fn general<S: Into<String>>(desc: S) -> Self {
        RoaesError::General {
            backtrace: Backtrace::generate(),
            desc: desc.into(),
        }
    }

    fn no_magic_number() -> Self {
        RoaesError::NoMagicNumber {}
    }

    fn incompatibility<S: Into<String>>(desc: S) -> Self {
        RoaesError::Incompatible {
            backtrace: Backtrace::generate(),
            desc: desc.into(),
        }
    }

    fn crypto<E: std::error::Error + Send + Sync + 'static, S: Into<String>>(
        err: E,
        desc: S,
    ) -> Self {
        RoaesError::Crypto {
            source: Box::new(err),
            backtrace: Backtrace::generate(),
            desc: desc.into(),
        }
    }

    /// Checks error for indicating the absence of the `OAES` magic number.
    pub fn is_no_valid_magic_number(&self) -> bool {
        matches!(self, RoaesError::NoMagicNumber)
    }
}
