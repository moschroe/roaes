use crate::util::{cipher_from_key, Aess, OaesFlags, OaesOptions, PaddingOaes};
use crate::{
    AesBlock, RoaesError, FILE_BLOCK_SIZE, FILE_BLOCK_SIZE64, OAES_BLOCK_SIZE, OAES_BLOCK_SIZE64,
};
use block_modes::block_padding::NoPadding;
use block_modes::{BlockMode, Cbc};
#[allow(unused_imports)]
use log::{debug, error, info, trace, warn};
use rand::rngs::OsRng;
use rand::RngCore;
#[cfg(test)]
use rhexdump::hexdump;
use std::cmp::min;
use std::io::{Cursor, Error as IOError, ErrorKind as IOErrorKind, Write};

/// Wraps a [Write] and transparently encrypts written data and encodes metadata in the openaes
/// format.
pub struct RoaesSink<W: Write> {
    sink: Option<W>,
    cipher: Aess,
    rand: OsRng,
    buffer: Cursor<Vec<u8>>,
    running_flush: bool,
    ignore_pipe: bool,
    #[cfg(test)]
    iv_forced: Vec<u8>,
}

impl<W: Write> std::fmt::Debug for RoaesSink<W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut dbg_struct = f.debug_struct("RoaesSink");
        dbg_struct
            .field("sink", &"<W>")
            .field("cipher", &self.cipher)
            .field("rand", &self.rand)
            .field("buffer", &"Cursor<Vec<u8>>, len: 4096")
            .field("running_flush", &self.running_flush)
            .field("ignore_pipe", &self.ignore_pipe);
        #[cfg(test)]
        dbg_struct.field(
            "iv_forced",
            &format_args!("{}", &rhexdump::hexdump(&self.iv_forced)),
        );
        dbg_struct.finish()
    }
}

impl<W: Write> RoaesSink<W> {
    /// Create a new `RoaesSink` with a given key.
    pub fn new(sink: W, key: &[u8]) -> Result<Self, RoaesError> {
        let cipher = cipher_from_key(key)?;
        Ok(RoaesSink {
            sink: Some(sink),
            cipher,
            rand: Default::default(),
            buffer: Cursor::new(vec![0; FILE_BLOCK_SIZE]),
            running_flush: false,
            ignore_pipe: false,
            #[cfg(test)]
            iv_forced: vec![0; OAES_BLOCK_SIZE],
        })
    }

    /// Consumes `self` and returns wrapped [Write].
    /// # Caution
    /// This will _not_ flush any buffer contents currently in flight, call [Self::flush()] to
    /// ensure contents are written to the underlying [Write]!
    pub fn into_inner(mut self) -> W {
        self.sink.take().expect(
            "As into_inner consumes the value, there should be no way to \
        call this method again",
        )
    }

    fn flush_buffer(&mut self) -> std::io::Result<()> {
        debug!("flushing buffer...");
        self.running_flush = true;
        // calculate offsets
        let pos64 = self.buffer.position();
        #[cfg(test)]
        trace!("pos64: {0} ({0:#x})", pos64);
        // if pos64 < 2 * OAES_BLOCK_SIZE64 + 1 {
        //     return Ok(());
        // }
        let pos_noheader = pos64 as usize - 2 * OAES_BLOCK_SIZE;
        let len_minimal = {
            let mut start = (pos64 / OAES_BLOCK_SIZE64) * OAES_BLOCK_SIZE64;
            if start < pos64 {
                trace!("start < pos64");
                start += OAES_BLOCK_SIZE64;
            }
            start as usize
        };
        assert!(
            len_minimal as u64 >= pos64,
            "offset calculation failed, minimal length {} not >= {}",
            len_minimal,
            pos64
        );
        let padding = len_minimal as u64 > pos64;
        #[cfg(test)]
        trace!(
            "len_minimal: {0} ({0:#x}), pos_noheader: {1}",
            len_minimal,
            pos_noheader
        );

        // write header
        self.write_header_block(padding)?;
        self.write_iv()?;
        // encrypt
        {
            let iv = &self.buffer.get_ref()[OAES_BLOCK_SIZE..OAES_BLOCK_SIZE + OAES_BLOCK_SIZE];
            debug!("encrypting...");
            match self.cipher.clone() {
                Aess::Aes128(a128) => {
                    if padding {
                        let cbc: Cbc<_, PaddingOaes> = Cbc::new(a128, AesBlock::from_slice(iv));
                        cbc.encrypt(
                            &mut self.buffer.get_mut()[OAES_BLOCK_SIZE * 2..len_minimal],
                            pos_noheader,
                        )
                        .map_err(|err_crypt| IOError::new(IOErrorKind::Other, err_crypt))?;
                    } else {
                        let cbc: Cbc<_, NoPadding> = Cbc::new(a128, AesBlock::from_slice(iv));
                        cbc.encrypt(
                            &mut self.buffer.get_mut()[OAES_BLOCK_SIZE * 2..len_minimal],
                            pos_noheader,
                        )
                        .map_err(|err_crypt| IOError::new(IOErrorKind::Other, err_crypt))?;
                    }
                }
                Aess::Aes192(a192) => {
                    if padding {
                        let cbc: Cbc<_, PaddingOaes> = Cbc::new(a192, AesBlock::from_slice(iv));
                        cbc.encrypt(
                            &mut self.buffer.get_mut()[OAES_BLOCK_SIZE * 2..len_minimal],
                            pos_noheader,
                        )
                        .map_err(|err_crypt| IOError::new(IOErrorKind::Other, err_crypt))?;
                    } else {
                        let cbc: Cbc<_, NoPadding> = Cbc::new(a192, AesBlock::from_slice(iv));
                        cbc.encrypt(
                            &mut self.buffer.get_mut()[OAES_BLOCK_SIZE * 2..len_minimal],
                            pos_noheader,
                        )
                        .map_err(|err_crypt| IOError::new(IOErrorKind::Other, err_crypt))?;
                    }
                }
                Aess::Aes256(a256) => {
                    if padding {
                        let cbc: Cbc<_, PaddingOaes> = Cbc::new(a256, AesBlock::from_slice(iv));
                        cbc.encrypt(
                            &mut self.buffer.get_mut()[OAES_BLOCK_SIZE * 2..len_minimal],
                            pos_noheader,
                        )
                        .map_err(|err_crypt| IOError::new(IOErrorKind::Other, err_crypt))?;
                    } else {
                        let cbc: Cbc<_, NoPadding> = Cbc::new(a256, AesBlock::from_slice(iv));
                        cbc.encrypt(
                            &mut self.buffer.get_mut()[OAES_BLOCK_SIZE * 2..len_minimal],
                            pos_noheader,
                        )
                        .map_err(|err_crypt| IOError::new(IOErrorKind::Other, err_crypt))?;
                    }
                }
            }
            #[cfg(test)]
            {
                trace!(
                    "after encryption...\n{}",
                    // hexdump(&self.buffer.get_ref()[..6 * OAES_BLOCK_SIZE])
                    //hexdump(self.buffer.get_ref())
                    hexdump(&self.buffer.get_ref()[..len_minimal])
                );
            }
        }
        self.sink
            .as_mut()
            .expect(
                "sink is set to Some at construction and only taken in \
        into_inner(), so it must be Some at this point",
            )
            .write_all(&self.buffer.get_ref()[..len_minimal])
            .map(|()| {
                self.buffer.set_position(0);
                self.running_flush = false;
            })
            .map_err(|err_io| {
                if err_io.kind() == IOErrorKind::BrokenPipe {
                    self.ignore_pipe = true;
                }
                err_io
            })
    }

    fn write_iv(&mut self) -> std::io::Result<()> {
        debug!("writing iv...");
        #[cfg(test)]
        {
            trace!(
                "empty buffer! doing IV...\n{}",
                hexdump(&self.buffer.get_ref()[..5 * OAES_BLOCK_SIZE])
            );
        }
        // skip header sub-block
        // choose & write IV
        self.buffer.set_position(OAES_BLOCK_SIZE64);
        let buf_iv = &mut self.buffer.get_mut()[OAES_BLOCK_SIZE..OAES_BLOCK_SIZE + OAES_BLOCK_SIZE];
        #[cfg(test)]
        {
            if !self.iv_forced.iter().all(|item| *item == 0x0) {
                // at least one non-null byte, use forced IV
                debug!("using forced IV");
                buf_iv.copy_from_slice(&self.iv_forced);
            } else {
                self.rand
                    .try_fill_bytes(buf_iv)
                    .map_err(|err_rnd| IOError::new(IOErrorKind::Other, err_rnd))?;
            }
        }
        #[cfg(not(test))]
        {
            self.rand
                .try_fill_bytes(buf_iv)
                .map_err(|err_rnd| IOError::new(IOErrorKind::Other, err_rnd))?;
        }
        #[cfg(test)]
        {
            trace!(
                "with IV...\n{}",
                hexdump(&self.buffer.get_ref()[..5 * OAES_BLOCK_SIZE])
            );
        }
        Ok(())
    }

    fn write_header_block(&mut self, padding: bool) -> std::io::Result<()> {
        debug!("writing header, padding: {}", padding);
        self.buffer.set_position(0);
        // write initial header
        // magic number
        self.buffer.write_all(b"OAES")?;
        // version 1, type 2
        self.buffer.write_all(&[0x1, 0x2])?;
        // options
        let opts = OaesOptions::CBC;
        self.buffer.write_all(&opts.bits().to_le_bytes())?;
        // flags
        let flags = if padding {
            OaesFlags::PADDING
        } else {
            OaesFlags::empty()
        };
        self.buffer.write_all(&flags.bits().to_be_bytes())?;
        // blot out reserved bits
        self.buffer.write_all(b"\0\0\0\0\0\0\0")?;
        #[cfg(test)]
        {
            trace!(
                "written header...\n{}",
                hexdump(&self.buffer.get_ref()[..5 * OAES_BLOCK_SIZE])
            );
        }
        Ok(())
    }
}

impl<W: Write> Write for RoaesSink<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        #[cfg(test)]
        trace!("writing {} bytes...", buf.len());
        if buf.is_empty() {
            return Ok(0);
        }
        let mut available = FILE_BLOCK_SIZE64 - self.buffer.position();
        if available == FILE_BLOCK_SIZE64 {
            available -= 2 * OAES_BLOCK_SIZE64;
            self.buffer.set_position(2 * OAES_BLOCK_SIZE64);
        } else if available == 0 {
            #[cfg(test)]
            trace!("available == 0, flushing buffer...");
            self.flush_buffer()?;
            available = FILE_BLOCK_SIZE64 - 2 * OAES_BLOCK_SIZE64;
            self.buffer.set_position(2 * OAES_BLOCK_SIZE64);
            #[cfg(test)]
            trace!(
                "flushed buffer, now @{}, available: {}",
                self.buffer.position(),
                available
            );
        }
        // write up to available bytes
        let transferrable = min(available as usize, buf.len());
        #[cfg(test)]
        trace!(
            "available: {}, buf.len(): {}, transferrable: {}",
            available,
            buf.len(),
            transferrable
        );
        self.buffer.write_all(&buf[..transferrable])?;
        #[cfg(test)]
        {
            trace!(
                "buffer post write...\n{}",
                hexdump(&self.buffer.get_ref()[..5 * OAES_BLOCK_SIZE])
            );
        }
        Ok(transferrable)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if self.buffer.position() == 0 {
            return Ok(());
        }
        self.flush_buffer()?;
        debug!("flushing sink...");
        self.sink
            .as_mut()
            .expect(
                "sink is set to Some at construction and only taken in \
        into_inner(), so it must be Some at this point",
            )
            .flush()
    }
}

impl<W: Write> Drop for RoaesSink<W> {
    fn drop(&mut self) {
        if self.ignore_pipe {
            info!("ignoring broken pipe on drop");
            return;
        }
        if self.buffer.position() != 0 {
            warn!(
                "Drop on RoaesSink called with un-flushed changes, error will only be logged! \
            For proper control flow call flush() manually!"
            );
            if self.running_flush || std::thread::panicking() {
                error!(
                    "interrupted operation or panicking detected, not flushing buffer \
                    at {} with {:?} unwritten bytes!",
                    self.buffer.position(),
                    self.buffer.position().checked_sub(2 * OAES_BLOCK_SIZE64)
                );
                return;
            }
            if let Err(err_io) = self.flush() {
                error!(
                    "error occurred flushing RoaesSink during drop: {:?}",
                    err_io
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::RoaesSink;
    use std::io::Write;

    const SAMPLE_KEY: &[u8] = include_bytes!("../../sample/key.txt");
    const IV_FORCED: &[u8] = b"abcdefghijklmnop";
    const PLAINTEXT_SHORT: &[u8] = include_bytes!("../../sample/plaintext_short.txt");
    const CIPHERTEXT_SHORT: &[u8] = include_bytes!("../../sample/ciphertext_short.bin");
    const PLAINTEXT_LONG: &[u8] = include_bytes!("../../sample/plaintext_long.txt");
    const CIPHERTEXT_LONG: &[u8] = include_bytes!("../../sample/ciphertext_long.bin");

    #[test]
    fn write_short() {
        let _ = env_logger::try_init().ok();

        let mut buf = Vec::with_capacity(1024);
        {
            let mut sink = RoaesSink::new(&mut buf, SAMPLE_KEY).unwrap();
            sink.iv_forced.copy_from_slice(IV_FORCED);

            sink.write_all(PLAINTEXT_SHORT).unwrap();
            sink.flush().unwrap();
        }
        assert_eq!(CIPHERTEXT_SHORT, &buf);
    }

    #[test]
    fn flush_immediately() {
        let _ = env_logger::try_init().ok();

        let mut buf = Vec::with_capacity(1024);
        {
            let mut sink = RoaesSink::new(&mut buf, SAMPLE_KEY).unwrap();
            sink.iv_forced.copy_from_slice(IV_FORCED);
            sink.flush().unwrap();
        }
        assert_eq!(
            0,
            buf.len(),
            "expected buffer to be empty after writing 0 byte"
        );
    }

    #[test]
    fn write_long() {
        let _ = env_logger::try_init().ok();

        let mut buf = Vec::with_capacity(1024);
        {
            let mut sink = RoaesSink::new(&mut buf, SAMPLE_KEY).unwrap();
            sink.iv_forced.copy_from_slice(IV_FORCED);

            sink.write_all(PLAINTEXT_LONG).unwrap();
            sink.flush().unwrap();
            dbg!(sink);
        }
        {
            let mut f = std::fs::File::create("sample/TEST.BIN").unwrap();
            f.write_all(&buf).unwrap();
            f.flush().unwrap();
        }

        assert_eq!(CIPHERTEXT_LONG, &buf);
    }

    #[test]
    fn write_parts() {
        let _ = env_logger::try_init().ok();

        let mut buf = Vec::with_capacity(1024);
        {
            let mut sink = RoaesSink::new(&mut buf, SAMPLE_KEY).unwrap();
            sink.iv_forced.copy_from_slice(IV_FORCED);

            let mut offset = 0;
            sink.write_all(&PLAINTEXT_SHORT[offset..offset + 3])
                .unwrap();
            offset = 3;
            sink.write_all(&PLAINTEXT_SHORT[offset..offset + 4])
                .unwrap();
            offset = 7;
            sink.write_all(&PLAINTEXT_SHORT[offset..offset + 4])
                .unwrap();
            offset = 11;
            sink.write_all(&PLAINTEXT_SHORT[offset..offset + 5])
                .unwrap();
            offset = 16;
            sink.write_all(&PLAINTEXT_SHORT[offset..]).unwrap();

            sink.flush().unwrap();
        }
        assert_eq!(CIPHERTEXT_SHORT, &buf);
    }
}
