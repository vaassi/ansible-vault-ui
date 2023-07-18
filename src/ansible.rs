use std::fs::File;
use std::io::{BufRead, Read};
use std::path::Path;

use aes::cipher::{KeyIvInit, StreamCipher};
use anyhow::{anyhow, Context, Result};
use block_padding::{Pkcs7, RawPadding};
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2;
use rand::Rng;
use sha2::Sha256;

pub const VAULT_1_1_PREFIX: &str = "$ANSIBLE_VAULT;1.1;AES256";
const AES_BLOCK_SIZE: usize = 16;
const KEY_SIZE: usize = 32;

type HmacSha256 = Hmac<Sha256>;
type Aes256Ctr = ctr::Ctr128BE<aes::Aes256>;

/// Verify vault data with derived key2 and hmac authentication
fn verify_vault(key: &[u8], ciphertext: &[u8], encrypted_hmac: &[u8]) -> Result<()> {
    let mut hmac = <HmacSha256 as Mac>::new_from_slice(key)?;
    hmac.update(ciphertext);

    Ok(hmac.verify_slice(encrypted_hmac)?)
}

/// Generate derived keys and initialization vector from given key and salt
fn generate_derived_key(key: &str, salt: &[u8]) -> ([u8; KEY_SIZE], [u8; KEY_SIZE], [u8; AES_BLOCK_SIZE]) {
    let mut hmac_buffer = [0; 2 * KEY_SIZE + AES_BLOCK_SIZE];
    let _ = pbkdf2::<HmacSha256>(key.as_bytes(), salt, 10_000, &mut hmac_buffer);

    let mut key1 = [0u8; KEY_SIZE];
    let mut key2 = [0u8; KEY_SIZE];
    let mut iv = [0u8; AES_BLOCK_SIZE];

    key1.copy_from_slice(&hmac_buffer[0..KEY_SIZE]);
    key2.copy_from_slice(&hmac_buffer[KEY_SIZE..2 * KEY_SIZE]);
    iv.copy_from_slice(&hmac_buffer[2 * KEY_SIZE..2 * KEY_SIZE + AES_BLOCK_SIZE]);

    (key1, key2, iv)
}

/// Decrypt ansible-vault payload (without header, no indentation nor carriage returns)
pub fn decrypt<T: Read>(mut input: T, key: &str) -> Result<Vec<u8>> {
    // read payload
    let mut payload = String::new();
    input.read_to_string(&mut payload)?;
    let unhex_payload = String::from_utf8(hex::decode(&payload)?)?;

    // extract salt, hmac and encrypted data
    let mut lines = unhex_payload.lines();
    let salt = hex::decode(
        lines
            .next()
            .context("invalid salt")?,
    )?;

    let hmac_verify = hex::decode(
        lines
            .next()
            .context("invalid hmac")?,
    )?;

    let mut ciphertext = hex::decode(
        lines
            .next()
            .context("invalid ciphertext")?,
    )?;

    // check data integrity
    let (key1, key2, iv) = &generate_derived_key(key, &salt);
    verify_vault(key2, &ciphertext, &hmac_verify)?;

    // decrypt message
    let mut cipher = <Aes256Ctr as KeyIvInit>::new_from_slices(key1, iv)?;
    cipher.apply_keystream(&mut ciphertext);

    let pos = Pkcs7::raw_unpad(&ciphertext[ciphertext.len() - AES_BLOCK_SIZE..])
        .map_err(|e| anyhow!(e))?.len();
    let pad_len = AES_BLOCK_SIZE - (pos % AES_BLOCK_SIZE);
    ciphertext.truncate(ciphertext.len() - pad_len);

    Ok(ciphertext)
}

pub fn decrypt_vault<T: Read>(input: T, key: &str) -> Result<Vec<u8>> {
    let mut lines = std::io::BufReader::new(input).lines();
    let first: String = lines
        .next()
        .context("not a vault")??;

    if first != VAULT_1_1_PREFIX {
        return Err(anyhow!("not a vault"));
    }

    let payload = lines
        .map_while(Result::ok)
        .map(|s| s.trim().to_owned())
        .collect::<Vec<String>>()
        .join("");

    decrypt(payload.as_bytes(), key)
}

/// Decrypt an ansible vault file using a key.
pub fn decrypt_vault_from_file<P: AsRef<Path>>(path: P, key: &str) -> Result<Vec<u8>> {
    let f = File::open(path)?;
    decrypt_vault(f, key)
}

/// Encrypt a message to an ansible vault formatted string
pub fn encrypt_vault<T: Read>(input: T, key: &str) -> Result<String> {
    let line_length = 80;
    let ciphertext = encrypt(input, key)?;
    let mut buffer = Vec::new();

    for chunk in ciphertext.into_bytes().chunks(line_length) {
        let mut line = [chunk, "\n".as_bytes()].concat();
        buffer.append(&mut line);
    }

    let vault_text = format! {"{}\n{}", VAULT_1_1_PREFIX, String::from_utf8(buffer)?};
    Ok(vault_text)
}

/// Encrypt message to string without formatting (no header, no carriage returns)
pub fn encrypt<T: Read>(mut input: T, key: &str) -> Result<String> {
    // Pad input data
    let mut buffer = Vec::new();
    input.read_to_end(&mut buffer)?;
    let pos = buffer.len();
    let pad_len = AES_BLOCK_SIZE - (pos % AES_BLOCK_SIZE);
    buffer.resize(pos + pad_len, 0);
    Pkcs7::raw_pad(&mut buffer[pos + pad_len - AES_BLOCK_SIZE..], AES_BLOCK_SIZE - pad_len);

    // Derive cryptographic keys
    let salt = rand::thread_rng().gen::<[u8; 32]>();
    let (key1, key2, iv) = &generate_derived_key(key, &salt);

    // Encrypt data
    let mut cipher = <Aes256Ctr as KeyIvInit>::new_from_slices(key1, iv)?;
    cipher.apply_keystream(&mut buffer);

    // Message authentication
    let mut mac = HmacSha256::new_from_slice(key2)?;
    mac.update(buffer.as_slice());
    let result = mac.finalize();
    let b_hmac = result.into_bytes();

    // Format data
    let ciphertext = format!(
        "{}\n{}\n{}",
        hex::encode(salt),
        hex::encode(b_hmac),
        hex::encode(buffer)
    );

    Ok(hex::encode(ciphertext))
}

/// Encrypt a file to an ansible_vault string
// pub fn encrypt_vault_from_file<P: AsRef<Path>>(path: P, key: &str) -> Result<String> {
//     let f = File::open(path)?;
//     encrypt_vault(f, key)
// }

#[cfg(test)]
mod tests {
    use std::fs;

    use crate::ansible::{decrypt_vault, decrypt_vault_from_file, encrypt_vault_from_file};

    const LIPSUM_PATH: &str = "./test/lipsum.txt";
    const LIPSUM_VAULT_PATH: &str = "./test/lipsum.vault";
    const LIPSUM_SECRET: &str = "123";

    #[test]
    fn test_wrong_password() {
        let result = decrypt_vault_from_file(LIPSUM_VAULT_PATH, "p@$$w0rd").unwrap_err();
        assert_eq!(result.to_string(), "MAC tag mismatch");
    }

    #[test]
    fn test_decrypt() {
        let buf = decrypt_vault_from_file(LIPSUM_VAULT_PATH, LIPSUM_SECRET).unwrap();
        let lipsum = String::from_utf8(buf).unwrap();
        let reference = fs::read_to_string(LIPSUM_PATH).unwrap();
        assert_eq!(lipsum, reference);
    }

    #[test]
    fn test_encrypt() {
        let lipsum = fs::read_to_string(LIPSUM_PATH).unwrap();
        let encoded = encrypt_vault_from_file(LIPSUM_PATH, LIPSUM_SECRET).unwrap();
        let decoded = decrypt_vault(encoded.as_bytes(), LIPSUM_SECRET).unwrap();
        let decoded_str = String::from_utf8(decoded).unwrap();
        assert_eq!(lipsum, decoded_str);
    }
}