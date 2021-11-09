use crate::RoaesError;
use aes::{Aes128, Aes192, Aes256, NewBlockCipher};
use bitflags::bitflags;
use block_modes::block_padding::{PadError, Padding, UnpadError};
use std::cmp::min;

#[derive(Clone)]
pub(crate) enum Aess {
    Aes128(Aes128),
    Aes192(Aes192),
    Aes256(Aes256),
}

impl std::fmt::Debug for Aess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Aess::Aes128(_) => {
                write!(f, "Aes128")
            }
            Aess::Aes192(_) => {
                write!(f, "Aes192")
            }
            Aess::Aes256(_) => {
                write!(f, "Aes256")
            }
        }
    }
}

bitflags! {
    pub(crate) struct OaesOptions: u16 {
        const ECB = 0b00000001;
        const CBC = 0b00000010;
        const DBG_STEP_ON = 0b00000100;
        const DBG_STEP_OFF = 0b00001000;
        const DBG_STEP_MISC = 0b00010000;
    }
}

bitflags! {
    pub(crate) struct OaesFlags: u8 {
        const PADDING = 0b00000001;
    }
}

#[derive(Debug, Copy, Clone)]
pub(crate) struct PaddingOaes;

impl Padding for PaddingOaes {
    fn pad_block(block: &mut [u8], pos: usize) -> Result<(), PadError> {
        if pos >= block.len() {
            return Err(PadError);
        }
        block
            .iter_mut()
            .skip(pos)
            .enumerate()
            .for_each(|(idx, byte)| {
                *byte = (idx + 1) as u8;
            });
        Ok(())
    }

    fn unpad(data: &[u8]) -> Result<&[u8], UnpadError> {
        if data.is_empty() {
            return Err(UnpadError);
        }
        let len_pad = data[data.len() - 1] as usize;
        if len_pad > data.len() {
            return Err(UnpadError);
        }
        Ok(&data[0..data.len() - len_pad])
    }
}

pub(crate) fn cipher_from_key(key: &[u8]) -> Result<Aess, RoaesError> {
    let mut key_data = [0u8; 32];
    PaddingOaes::pad_block(&mut key_data, 0)
        .map_err(|err| RoaesError::general(format!("unable to pre-pad key data: {:?}", err)))?;
    let aes: Aess;
    if key.len() <= 16 {
        // pad key
        key_data[0..key.len()].copy_from_slice(key);
        aes = Aes128::new_from_slice(&key_data[..16])
            .map_err(|err| {
                RoaesError::general(format!("unable to create Aes128 instance: {:?}", err))
            })
            .map(Aess::Aes128)?;
    } else if key.len() <= 24 {
        // pad key
        key_data[0..key.len()].copy_from_slice(key);
        aes = Aes192::new_from_slice(&key_data[..24])
            .map_err(|err| {
                RoaesError::general(format!("unable to create Aes192 instance: {:?}", err))
            })
            .map(Aess::Aes192)?;
    } else {
        // pad key
        key_data[0..min(32, key.len())].copy_from_slice(key);
        aes = Aes256::new_from_slice(&key_data[..32])
            .map_err(|err| {
                RoaesError::general(format!("unable to create Aes256 instance: {:?}", err))
            })
            .map(Aess::Aes256)?;
    }
    Ok(aes)
}
