use std::{
    cmp,
    convert::TryInto,
};

use aes::{Aes128, Aes256};
use block_modes::{BlockMode, Cbc, Ecb};
use block_padding::{NoPadding, Padding, Pkcs7};
use cipher::generic_array::GenericArray;
use thiserror::Error;

/// Block size for encrypted data
pub const BLOCK_SIZE: usize = 32;
/// Key size
pub const KEY_SIZE: usize = 32;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Fixed key has incorrect length")]
    IncorrectFixedKeyLength,
    #[error("Flexible key suffix has incorrect length")]
    IncorrectFlexibleKeySuffixLength,
    #[error("Ciphertext is smaller than block size")]
    CiphertextTooSmall,
}

/// Container for holding FUS encryption keys.
#[derive(Clone, Debug)]
pub struct FusKeys {
    pub fixed_key: [u8; 32],
    pub flexible_key_suffix: [u8; 16],
}

impl FusKeys {
    /// Load keys from the specified byte slices. The fixed key should be 32
    /// bytes and the flexible key suffix should be 16 bytes.
    pub fn new(
        fixed_key: &[u8],
        flexible_key_suffix: &[u8],
    ) -> Result<Self, CryptoError> {
        Ok(Self {
            fixed_key: fixed_key.try_into()
                .map_err(|_| CryptoError::IncorrectFixedKeyLength)?,
            flexible_key_suffix: flexible_key_suffix.try_into()
                .map_err(|_| CryptoError::IncorrectFlexibleKeySuffixLength)?,
        })
    }

    /// Derive the FUS "flexible key" from a list of indexes of the fixed key +
    /// a hardcoded suffix.
    pub fn get_flexible_key_from_indexes(&self, key_indexes: &[usize]) -> Vec<u8> {
        key_indexes.iter()
            .map(|i| self.fixed_key[*i])
            .chain(self.flexible_key_suffix.iter().copied())
            .collect()
    }

    /// Derive the FUS "flexible key" from the given base. Mod 16 is applied to
    /// each element to form the fixed key index list.
    pub fn get_flexible_key(&self, key_base: &[u8]) -> Vec<u8> {
        let indexes: Vec<usize> = key_base.iter()
            .map(|x| (x % 16) as usize)
            .collect();

        self.get_flexible_key_from_indexes(&indexes)
    }
}

/// Pad byte array to specified block size and optionally truncate to one block.
fn pad(mut data: &[u8], block_size: usize, truncate_to_block_size: bool) -> Vec<u8> {
    if truncate_to_block_size {
        data = &data[..cmp::min(data.len(), block_size)];
    }
    let mut buf = data.to_vec();

    if data.is_empty() || data.len() % block_size != 0 {
        buf.resize((data.len() / block_size + 1) * block_size, 0);
        Pkcs7::pad(&mut buf, data.len(), block_size).unwrap();
    }

    buf
}

/// Type for performing AES operations in the way that FUS expects. Notably:
/// * The key is PKCS#7 padded to 32 bytes if it is too short or truncated to
///   32 bytes if it is too long.
/// * The data uses a 32-byte block size. It is PKCS#7 padded to the next
///   32-byte boundary. During decryption, if the input is a multiple of
///   32-bytes and the last block looks like it has padding, then the padding
///   will be truncated. There is no way to tell the difference between padding
///   and some bytes that look like padding.
///
/// If AES-NI is supported, it will be used.
pub struct FusAes256(Cbc<Aes256, NoPadding>);

impl FusAes256 {
    /// Create a new cipher instance to perform AES operations in the way that
    /// FUS expects. The key will be PKCS#7 padded to 32 bytes if it is too
    /// short or truncated to 32 bytes if it is too long.
    pub fn new(key: &[u8]) -> Self {
        let padded_key = pad(key, KEY_SIZE, true);
        let iv = &padded_key[..16];

        let ga_key = GenericArray::from_slice(&padded_key);
        let ga_iv = GenericArray::from_slice(iv);

        let cipher = Cbc::<Aes256, NoPadding>::new_fix(ga_key, ga_iv);
        Self(cipher)
    }

    /// Encrypt the provided plaintext data. The data will be PKCS#7 padded to
    /// the next 32-byte boundary.
    pub fn encrypt(self, data: &[u8]) -> Vec<u8> {
        let mut buf = pad(data, BLOCK_SIZE, false);
        let buf_size = buf.len();

        self.0.encrypt(&mut buf, buf_size).unwrap();

        buf
    }

    /// Decrypt the provided FUS ciphertext. The returned plain text will be
    /// PKCS#7 unpadded.
    pub fn decrypt(self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut plaintext = self.0.decrypt_vec(data)
            .map_err(|_| CryptoError::CiphertextTooSmall)?;

        let plaintext_len = match Pkcs7::unpad(&plaintext) {
            Ok(s) => s.len(),
            Err(_) => plaintext.len(), // Assume unpadded
        };

        plaintext.resize(plaintext_len, 0);
        Ok(plaintext)
    }
}

/// Type for decrypting files downloaded from FUS. This is just normal
/// AES128-ECB with no padding.
///
/// If AES-NI is supported, it will be used.
#[derive(Clone)]
pub struct FusFileAes128(Ecb<Aes128, NoPadding>);

impl FusFileAes128 {
    /// Create a new cipher instance for decrypting FUS files.
    pub fn new(key: &[u8]) -> Self {
        let ga_key = GenericArray::from_slice(key);
        let ga_iv = &GenericArray::default();

        let cipher = Ecb::<Aes128, NoPadding>::new_fix(ga_key, ga_iv);
        Self(cipher)
    }

    /// Decrypt the provided ciphertext in-place.
    pub fn decrypt_in_place(self, buf: &mut [u8]) -> Result<(), CryptoError> {
        self.0.decrypt(buf)
            .map_err(|_| CryptoError::CiphertextTooSmall)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use hex_literal::hex;

    use super::*;

    #[test]
    fn test_pad() {
        let key = b"0123";
        assert_eq!(pad(key, 4, false), key);
        assert_eq!(pad(key, 4, true), key);

        let key = b"";
        assert_eq!(pad(key, 4, false), [4, 4, 4, 4]);
        assert_eq!(pad(key, 4, true), [4, 4, 4, 4]);

        let key = b"01234";
        assert_eq!(pad(key, 4, false), b"01234\x03\x03\x03");
        assert_eq!(pad(key, 4, true), b"0123");

        let key = b"01234567";
        assert_eq!(pad(key, 4, false), b"01234567");
        assert_eq!(pad(key, 4, true), b"0123");
    }

    #[test]
    fn test_create_flexible_key() {
        let keys = FusKeys::new(
            b"testing_testing_testing_testing_",
            b"testing_testing_",
        ).unwrap();

        assert_eq!(keys.get_flexible_key_from_indexes(&[]), b"testing_testing_");
        assert_eq!(keys.get_flexible_key_from_indexes(&[1, 2, 3]), b"esttesting_testing_");

        assert_eq!(keys.get_flexible_key(b""), b"testing_testing_");
        assert_eq!(keys.get_flexible_key(b"abc"), b"esttesting_testing_");
    }

    #[test]
    fn test_encrypt() {
        // Key smaller than IV length
        assert_eq!(FusAes256::new(b"testing_").encrypt(b""),
                   hex!("ba575394750d7028b1ebf23bb82ad8978a2bb2183a0db9ca0d01f3f18c764eb4"));

        // Key equal to IV length
        assert_eq!(FusAes256::new(b"testing_testing_").encrypt(b""),
                   hex!("dd3b9041a4d4f8be4c6aa4cee25776670d3d7ce4383f68f65bbb037575beb7cd"));

        // Key equal to max key length
        assert_eq!(FusAes256::new(b"testing_testing_testing_testing_").encrypt(b""),
                   hex!("bccdc940c00de876757aa90693b01dab21ebefa70e46b4cb4ae2343b75c460d3"));

        // Key larger than max key length (truncation)
        assert_eq!(FusAes256::new(b"testing_testing_testing_testing_testing_").encrypt(b""),
                   hex!("bccdc940c00de876757aa90693b01dab21ebefa70e46b4cb4ae2343b75c460d3"));

        // Data equal to block size
        assert_eq!(FusAes256::new(b"testing_testing_testing_testing_testing_")
                       .encrypt(b"testing_testing_testing_testing_"),
                   hex!("cab26214eca0a48c67ab89db59d4f6341d9dee81cc7e31906d8161a9eb90aad6"));

        // Data not equal to block size
        assert_eq!(FusAes256::new(b"testing_testing_testing_testing_testing_")
                       .encrypt(b"testing_testing_"),
                   hex!("cab26214eca0a48c67ab89db59d4f634b93539dbbc9b9fb37052902f83f35740"));
    }

    #[test]
    fn test_decrypt() {
        // Empty ciphertext
        assert_matches!(FusAes256::new(b"testing_testing_").decrypt(b""),
                        Ok(x) if x == b"");

        // Ciphertext not multiple of block size
        assert_matches!(FusAes256::new(b"testing_testing_").decrypt(&[0]),
                        Err(CryptoError::CiphertextTooSmall));

        // Ciphertext with invalid padding should not be unpadded
        assert_matches!(FusAes256::new(b"testing_testing_")
                            .decrypt(&hex!("ea016b97268c45b6201797452df6c688ae6fe6a2b756275f4528464339aca48e")),
                        Ok(x) if x == hex!("74657374696e675f74657374696e675f10101010101010101010101010101002"));

        // Padding is correctly removed
        assert_matches!(FusAes256::new(b"testing_testing_")
                            .decrypt(&hex!("ea016b97268c45b6201797452df6c688a70500f3e18d557474c10a55758b07d9")),
                        Ok(x) if x == hex!("74657374696e675f74657374696e675f"));
    }
}
