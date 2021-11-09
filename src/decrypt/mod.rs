use crate::util::{cipher_from_key, Aess, OaesFlags, OaesOptions, PaddingOaes};
use crate::{AesBlock, RoaesError, FILE_BLOCK_SIZE, IO, OAES_BLOCK_SIZE};
use block_modes::block_padding::NoPadding;
use block_modes::{BlockMode, Cbc};
use snafu::ResultExt;
use std::cmp::min;
use std::io::{Error as IOError, ErrorKind as IOErrorKind, Read};

#[derive(Debug)]
struct RoaesSourceState {
    cipher: Aess,

    pos: usize,
    pos_global: usize,
}

impl RoaesSourceState {
    fn with_cipher<R2: Read>(
        mut input: R2,
        cipher: Aess,
        buffer: &mut Vec<u8>,
    ) -> Result<Option<RoaesSourceState>, RoaesError> {
        assert!(
            buffer.capacity() >= FILE_BLOCK_SIZE,
            "buffer capacity {} was not >= {}",
            buffer.capacity(),
            FILE_BLOCK_SIZE
        );
        unsafe {
            // Ok since u8 do not have a drop impl and we made sure to allocate this much memory
            buffer.set_len(FILE_BLOCK_SIZE);
        }

        // try to read into buffer
        let len_file_block = input.read(buffer.as_mut_slice()).context(IO {
            desc: "unable to read ciphertext into buffer",
        })?;
        if len_file_block == 0 {
            // signal EOF
            return Ok(None);
        }
        if len_file_block % OAES_BLOCK_SIZE != 0 {
            return Err(RoaesError::underflow_multiple_aes_block(len_file_block));
        }
        buffer.truncate(len_file_block);

        let pos_global = len_file_block;
        let mut buffer_read = buffer.as_slice();
        // try read header
        let mut header = [0u8; OAES_BLOCK_SIZE];
        buffer_read.read_exact(&mut header).context(IO {
            desc: "unable to read 16 header bytes",
        })?;
        let header = header;
        if &header[0..4] != b"OAES" {
            return Err(RoaesError::no_magic_number());
        }
        if header[4] != 0x1 {
            return Err(RoaesError::incompatibility("header did not have version 1"));
        }
        if header[5] != 0x2 {
            return Err(RoaesError::incompatibility("header did not have type 2"));
        }

        let bits = header[6] as u16 | ((header[7] as u16) << 8);
        let options = OaesOptions::from_bits(bits)
            .ok_or_else(|| RoaesError::incompatibility("unknown option set in header"))?;
        if !options.contains(OaesOptions::CBC) {
            return Err(RoaesError::incompatibility("only CBC mode supported"));
        }
        let flags = OaesFlags::from_bits(header[8])
            .ok_or_else(|| RoaesError::incompatibility("unknown flag set in header"))?;

        let mut iv = [0u8; OAES_BLOCK_SIZE];
        buffer_read.read_exact(&mut iv).context(IO {
            desc: "unable to read 16 iv bytes",
        })?;
        let iv = iv;

        let flag_padding = flags.contains(OaesFlags::PADDING);
        let buf_no_padding = match &cipher {
            Aess::Aes128(aes) => if flag_padding {
                let cbc: Cbc<_, PaddingOaes> = Cbc::new(aes.clone(), AesBlock::from_slice(&iv));
                cbc.decrypt(&mut buffer[OAES_BLOCK_SIZE * 2..])
            } else {
                let cbc: Cbc<_, NoPadding> = Cbc::new(aes.clone(), AesBlock::from_slice(&iv));
                cbc.decrypt(&mut buffer[OAES_BLOCK_SIZE * 2..])
            }
            .map_err(|err| RoaesError::crypto(err, "unable to decrypt block"))?,
            Aess::Aes192(aes) => if flag_padding {
                let cbc: Cbc<_, PaddingOaes> = Cbc::new(aes.clone(), AesBlock::from_slice(&iv));
                cbc.decrypt(&mut buffer[OAES_BLOCK_SIZE * 2..])
            } else {
                let cbc: Cbc<_, NoPadding> = Cbc::new(aes.clone(), AesBlock::from_slice(&iv));
                cbc.decrypt(&mut buffer[OAES_BLOCK_SIZE * 2..])
            }
            .map_err(|err| RoaesError::crypto(err, "unable to decrypt block"))?,
            Aess::Aes256(aes) => if flag_padding {
                let cbc: Cbc<_, PaddingOaes> = Cbc::new(aes.clone(), AesBlock::from_slice(&iv));
                cbc.decrypt(&mut buffer[OAES_BLOCK_SIZE * 2..])
            } else {
                let cbc: Cbc<_, NoPadding> = Cbc::new(aes.clone(), AesBlock::from_slice(&iv));
                cbc.decrypt(&mut buffer[OAES_BLOCK_SIZE * 2..])
            }
            .map_err(|err| RoaesError::crypto(err, "unable to decrypt block"))?,
        };
        let len_no_padding = buf_no_padding.len();

        buffer.truncate(2 * OAES_BLOCK_SIZE + len_no_padding);

        Ok(Some(RoaesSourceState {
            cipher,
            pos: 2 * OAES_BLOCK_SIZE,
            pos_global,
        }))
    }
}

/// Wraps a [Read] and transparently decodes openaes metadata and decrypts the contents.
#[derive(Debug)]
pub struct RoaesSource<R>
where
    R: Read,
{
    input: R,
    buffer: Vec<u8>,
    state: RoaesSourceState,
}

impl<R> RoaesSource<R>
where
    R: Read,
{
    /// Create new `RoaesSource` with given key.
    pub fn new(mut input: R, key: &[u8]) -> Result<Self, RoaesError> {
        let mut buffer = vec![0; FILE_BLOCK_SIZE];
        RoaesSourceState::with_cipher(&mut input, cipher_from_key(key)?, &mut buffer)
            .transpose()
            .ok_or(RoaesError::Eof)?
            .map(|state| RoaesSource {
                input,
                buffer,
                state,
            })
    }

    /// Consumes `self` and returns wrapped [Read].
    pub fn into_inner(self) -> R {
        self.input
    }

    /// Check [Read] for starting with the openaes magic number `b"OAES"`.
    pub fn has_magic_number(mut read: R) -> Result<bool, RoaesError> {
        let mut buf = [0u8; 4];
        read.read_exact(&mut buf)
            .map(|()| <[u8; 4] as AsRef<[u8]>>::as_ref(&buf) == b"OAES")
            .or_else(|err| {
                if err.kind() == IOErrorKind::UnexpectedEof {
                    Ok(false)
                } else {
                    Err(err)
                }
            })
            .context(IO {
                desc: "attempting to read 4 bytes to check for OAES magic number",
            })
    }
}

impl<R: Read> Read for RoaesSource<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.state.pos == self.buffer.len() {
            // buffer exhausted, try reading next file block
            match RoaesSourceState::with_cipher(
                &mut self.input,
                self.state.cipher.clone(),
                &mut self.buffer,
            )
            .map_err(|err| IOError::new(IOErrorKind::Other, err))?
            {
                Some(state) => {
                    self.state = state;
                }
                None => {
                    self.state.pos = usize::MAX;
                }
            }
        }
        if self.state.pos == usize::MAX {
            // at EOF
            return Ok(0);
        }
        let available = self.buffer.len() - self.state.pos;
        let transferrable = min(buf.len(), available);
        buf[0..transferrable]
            .copy_from_slice(&self.buffer[self.state.pos..self.state.pos + transferrable]);
        self.state.pos += transferrable;
        Ok(transferrable)
    }
}

#[cfg(test)]
mod tests {
    #![allow(dead_code)]

    use crate::RoaesSource;
    use std::io::Read;

    const SAMPLE_CIPHERTEXT: &[u8] = include_bytes!("../../sample/date_enc");
    const SAMPLE_PLAINTEXT: &[u8] = include_bytes!("../../sample/date_plain");
    const SAMPLE_KEY: &[u8] = include_bytes!("../../sample/key.txt");

    #[test]
    fn read_whole() {
        let mut r = RoaesSource::new(SAMPLE_CIPHERTEXT, SAMPLE_KEY).unwrap();

        let mut decrypted = Vec::with_capacity(10);
        let pos_new = r.read_to_end(&mut decrypted).unwrap();
        assert_eq!(SAMPLE_PLAINTEXT, &decrypted[0..pos_new]);
        assert_eq!(SAMPLE_PLAINTEXT, &decrypted);
    }

    #[test]
    fn read_parts() {
        let mut r = RoaesSource::new(SAMPLE_CIPHERTEXT, SAMPLE_KEY).unwrap();
        let mut offset = 0;
        let mut decrypted = Vec::with_capacity(48);
        decrypted.resize(64, 0);
        offset += r.read(&mut decrypted[offset..offset + 15]).unwrap();
        assert_eq!(&SAMPLE_PLAINTEXT[0..offset], &decrypted[0..offset]);

        offset += r.read(&mut decrypted[offset..offset + 2]).unwrap();
        assert_eq!(&SAMPLE_PLAINTEXT[0..offset], &decrypted[0..offset]);

        offset += r.read(&mut decrypted[offset..offset + 5]).unwrap();
        assert_eq!(&SAMPLE_PLAINTEXT[0..offset], &decrypted[0..offset]);

        offset += r.read(&mut decrypted[offset..offset + 15]).unwrap();
        assert_eq!(&SAMPLE_PLAINTEXT[0..offset], &decrypted[0..offset]);

        offset += r.read(&mut decrypted[offset..offset + 15]).unwrap();
        assert_eq!(&SAMPLE_PLAINTEXT[0..offset], &decrypted[0..offset]);

        offset += r.read(&mut decrypted[offset..offset + 15]).unwrap();
        assert_eq!(&SAMPLE_PLAINTEXT[0..offset], &decrypted[0..offset]);

        offset += r.read(&mut decrypted[offset..offset + 15]).unwrap();
        assert_eq!(&SAMPLE_PLAINTEXT[0..offset], &decrypted[0..offset]);
        assert_eq!(SAMPLE_PLAINTEXT, &decrypted[0..33]);
    }
}
