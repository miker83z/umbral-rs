pub use crate::errors::PreErrors;

use chacha20poly1305::{
  aead::{Aead, NewAead},
  ChaCha20Poly1305, Key, Nonce,
};
use crypto_api_blake2::Blake2b;

const DEM_KEYSIZE: usize = 32;
const DEM_NONCE_SIZE: usize = 12;
pub const DEM_MIN_SIZE: usize = DEM_NONCE_SIZE + 16 + 1;

pub fn kdf(base_key: &Vec<u8>) -> Result<Vec<u8>, PreErrors> {
  let mut buf = vec![0; DEM_KEYSIZE];
  let salt = vec![0; 16]; //TODO
  let info = vec![0; 16]; //TODO

  match Blake2b::kdf().derive(&mut buf, base_key, &salt, &info) {
    Ok(_) => Ok(buf),
    Err(_) => Err(PreErrors::DerivationError),
  }
}

pub fn dem_encrypt(key: &Vec<u8>, plaintext: &Vec<u8>) -> Result<Vec<u8>, PreErrors> {
  // optional authenticated data is missing
  let secret_key = Key::from_slice(key); // 32-bytes
  let cipher = ChaCha20Poly1305::new(secret_key);

  let mut slice = [0u8; DEM_NONCE_SIZE];
  getrandom::getrandom(&mut slice).expect("Error in Encryption nonce generation");
  let nonce = Nonce::from_slice(&slice); // 12-bytes; unique per message

  match cipher.encrypt(nonce, plaintext.as_slice()) {
    Ok(mut enc_data) => {
      let mut ciphertext = nonce.to_vec();
      ciphertext.append(&mut enc_data);
      Ok(ciphertext)
    }
    Err(_) => Err(PreErrors::EncryptionError),
  }
}

pub fn dem_decrypt(key: &Vec<u8>, ciphertext: &Vec<u8>) -> Result<Vec<u8>, PreErrors> {
  // optional authenticated data is missing
  let secret_key = Key::from_slice(key); // 32-bytes
  let cipher = ChaCha20Poly1305::new(secret_key);

  let nonce = Nonce::from_slice(&ciphertext[..DEM_NONCE_SIZE]); // 12-bytes; unique per message

  match cipher.decrypt(nonce, &ciphertext[DEM_NONCE_SIZE..]) {
    Ok(p) => Ok(p),
    Err(_) => Err(PreErrors::DecryptionError),
  }
}
