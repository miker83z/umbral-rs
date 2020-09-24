use crate::internal::curve::{CurveBN, Params};
use crate::internal::errors::PreErrors;

use std::rc::Rc;

use blake2::{Blake2b, Digest};
use chacha20poly1305::{
  aead::{Aead, NewAead, Payload},
  ChaCha20Poly1305, Key, Nonce,
};
use hkdf::Hkdf;
use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroupRef, EcPoint};
use sha2::Sha256;
use sha3::Keccak256;

const DEM_KEYSIZE: usize = 32;
const DEM_NONCE_SIZE: usize = 12;
pub const DEM_MIN_SIZE: usize = DEM_NONCE_SIZE + 16 + 1;
const CUSTOMIZATION_STRING_LENGTH: usize = 64;
const CUSTOMIZATION_STRING_PAD: &[u8; 1] = b"\x00";

pub trait Hash {
  fn new(customization_string: &Vec<u8>) -> Self;
  fn update(&mut self, data: &Vec<u8>);
  fn copy(&self) -> Self;
  fn finalize(self) -> Vec<u8>;
}

pub struct Blake2bHash {
  digest: Blake2b,
}

impl Hash for Blake2bHash {
  fn new(customization_string: &Vec<u8>) -> Self {
    let mut new_c = customization_string.clone();
    let rem = (CUSTOMIZATION_STRING_LENGTH as i64) - (new_c.len() as i64);
    if rem < 0 {
      panic!(
        "Customization string is larger than {} characters",
        CUSTOMIZATION_STRING_LENGTH
      ); //maybe TODO
    }
    for _ in 0..rem {
      new_c.append(&mut CUSTOMIZATION_STRING_PAD.to_owned().to_vec());
    }
    let mut hasher = Blake2b::new();
    hasher.update(new_c);

    Self { digest: hasher }
  }

  fn update(&mut self, data: &Vec<u8>) {
    self.digest.update(data);
  }

  fn copy(&self) -> Self {
    Self {
      digest: self.digest.clone(),
    }
  }

  fn finalize(self) -> Vec<u8> {
    self.digest.finalize().to_vec()
  }
}

pub struct ExtendedKeccak {
  upper: Keccak256,
  lower: Keccak256,
}

impl Hash for ExtendedKeccak {
  fn new(customization_string: &Vec<u8>) -> Self {
    let upper_prefix = b"\x00";
    let lower_prefix = b"\x01";

    let mut new_c = customization_string.clone();
    let rem = (CUSTOMIZATION_STRING_LENGTH as i64) - (new_c.len() as i64);
    if rem < 0 {
      panic!(
        "Customization string is larger than {} characters",
        CUSTOMIZATION_STRING_LENGTH
      ); //maybe TODO
    }
    for _ in 0..rem {
      new_c.append(&mut CUSTOMIZATION_STRING_PAD.to_owned().to_vec());
    }
    let mut upper = Keccak256::new();
    upper.update(upper_prefix);
    upper.update(&new_c);
    let mut lower = Keccak256::new();
    lower.update(lower_prefix);
    lower.update(&new_c);

    Self { upper, lower }
  }

  fn update(&mut self, data: &Vec<u8>) {
    self.upper.update(data);
    self.lower.update(data);
  }

  fn copy(&self) -> Self {
    Self {
      upper: self.upper.clone(),
      lower: self.lower.clone(),
    }
  }

  fn finalize(self) -> Vec<u8> {
    let mut up = self.upper.finalize().to_vec().clone();
    let mut lo = self.lower.finalize().to_vec().clone();
    up.append(&mut lo);
    up
  }
}

pub struct SHA256Hash {
  digest: Sha256,
}

impl Hash for SHA256Hash {
  fn new(customization_string: &Vec<u8>) -> Self {
    let mut new_c = customization_string.clone();
    let rem = (CUSTOMIZATION_STRING_LENGTH as i64) - (new_c.len() as i64);
    if rem < 0 {
      panic!(
        "Customization string is larger than {} characters",
        CUSTOMIZATION_STRING_LENGTH
      ); //maybe TODO
    }
    for _ in 0..rem {
      new_c.append(&mut CUSTOMIZATION_STRING_PAD.to_owned().to_vec());
    }
    let mut hasher = Sha256::new();
    hasher.update(new_c);

    Self { digest: hasher }
  }

  fn update(&mut self, data: &Vec<u8>) {
    self.digest.update(data);
  }

  fn copy(&self) -> Self {
    Self {
      digest: self.digest.clone(),
    }
  }

  fn finalize(self) -> Vec<u8> {
    self.digest.finalize().to_vec()
  }
}

pub fn hash_to_curve_blake(bytes: &Vec<u8>, params: &Rc<Params>) -> CurveBN {
  hash_to_curvebn::<Blake2bHash>(bytes, params, None)
}

pub fn hash_to_curvebn<H>(
  bytes: &Vec<u8>,
  params: &Rc<Params>,
  customization_string: Option<&Vec<u8>>,
) -> CurveBN
where
  H: Hash,
{
  let mut htc_customization = b"hash_to_curvebn".to_vec();
  let final_customization = match customization_string {
    Some(c) => {
      htc_customization.append(&mut c.clone());
      htc_customization
    }
    None => htc_customization,
  };
  let mut hash = H::new(&final_customization);
  hash.update(bytes);

  let digest_bn = BigNum::from_slice(&hash.finalize()).expect("Error in BN creation");

  // Get order minus one
  let one = BigNum::from_dec_str("1").expect("Error in BN creation");
  let mut order_minus_one = BigNum::new().expect("Error in BN creation");
  order_minus_one
    .checked_sub(params.order(), &one)
    .expect("Error in BN subtraction");

  // Compute modulo
  let mut modulo = BigNum::new().expect("Error in BN creation");
  modulo
    .checked_rem(&digest_bn, &order_minus_one, &mut params.ctx().borrow_mut())
    .expect("Error in BN modulo");

  // To CurveBN
  let mut curve_bn = BigNum::new().expect("Error in BN creation");
  curve_bn
    .checked_add(&modulo, &one)
    .expect("Error in BN addition");

  CurveBN::from_big_num(&curve_bn, params)
}

pub fn kdf(base_key: &Vec<u8>) -> Result<Vec<u8>, PreErrors> {
  kdf_args(base_key, None, None)
}

pub fn kdf_args(
  base_key: &Vec<u8>,
  salt: Option<Vec<u8>>,
  info: Option<Vec<u8>>,
) -> Result<Vec<u8>, PreErrors> {
  let s = match salt {
    Some(x) => x,
    None => vec![0; DEM_KEYSIZE / 8],
  };
  let info = match info {
    Some(x) => x,
    None => vec![0; 0],
  };
  let mut buf = vec![0; DEM_KEYSIZE];
  match Hkdf::<Blake2b>::new(Some(&s), &base_key).expand(&info, &mut buf) {
    Ok(_) => Ok(buf),
    Err(_) => Err(PreErrors::DerivationError),
  }
}

pub fn dem_encrypt(
  key: &Vec<u8>,
  plaintext: &Vec<u8>,
  aad: Option<&Vec<u8>>,
) -> Result<Vec<u8>, PreErrors> {
  let secret_key = Key::from_slice(key); // 32-bytes
  let cipher = ChaCha20Poly1305::new(secret_key);

  let mut slice = [0u8; DEM_NONCE_SIZE];
  getrandom::getrandom(&mut slice).expect("Error in Encryption nonce generation");
  let nonce = Nonce::from_slice(&slice); // 12-bytes; unique per message
  let payload = match aad {
    Some(a) => Payload {
      msg: plaintext,
      aad: a,
    },
    None => Payload {
      msg: plaintext,
      aad: b"",
    },
  };

  match cipher.encrypt(nonce, payload) {
    Ok(mut enc_data) => {
      let mut ciphertext = nonce.to_vec();
      ciphertext.append(&mut enc_data);
      Ok(ciphertext)
    }
    Err(_) => Err(PreErrors::EncryptionError),
  }
}

pub fn dem_decrypt(
  key: &Vec<u8>,
  ciphertext: &Vec<u8>,
  aad: Option<&Vec<u8>>,
) -> Result<Vec<u8>, PreErrors> {
  let secret_key = Key::from_slice(key); // 32-bytes
  let cipher = ChaCha20Poly1305::new(secret_key);

  let nonce = Nonce::from_slice(&ciphertext[..DEM_NONCE_SIZE]); // 12-bytes; unique per message
  let payload = match aad {
    Some(a) => Payload {
      msg: &ciphertext[DEM_NONCE_SIZE..],
      aad: a,
    },
    None => Payload {
      msg: &ciphertext[DEM_NONCE_SIZE..],
      aad: b"",
    },
  };

  match cipher.decrypt(nonce, payload) {
    Ok(p) => Ok(p),
    Err(err) => {
      println!("{}", err);
      return Err(PreErrors::DecryptionError);
    }
  }
}

pub fn unsafe_hash_to_point<H>(
  bytes: Option<&Vec<u8>>,
  label_bytes: Option<&Vec<u8>>,
  group: &EcGroupRef,
  ctx: &mut BigNumContext,
) -> EcPoint
where
  H: Hash,
{
  let mut data = b"".to_vec();
  match bytes {
    Some(d) => data.append(&mut d.clone()),
    None => (),
  };
  let mut label = b"".to_vec();
  match label_bytes {
    Some(l) => label.append(&mut l.clone()),
    None => (),
  };
  // Lengths
  let mut len_data = data.len().to_be_bytes().to_vec();
  let mut to_hash = label.len().to_be_bytes().to_vec();

  // Data to hash
  to_hash.append(&mut label);
  to_hash.append(&mut len_data);
  to_hash.append(&mut data);

  let curve_key_size_bytes = ((group.degree() + 7) / 8) as usize;

  for i in 0..2usize.pow(32) {
    let ibytes = i.to_be_bytes().to_vec();
    let mut hash = H::new(&b"".to_vec());
    hash.update(&to_hash);
    hash.update(&ibytes);

    let digest = &hash.finalize()[..(curve_key_size_bytes + 1)];

    let mut compressed_point = match digest[0] & 1 == 0 {
      true => b"\x02".to_vec(),
      false => b"\x02".to_vec(),
    };
    compressed_point.append(&mut digest[1..].to_vec());

    match EcPoint::from_bytes(group, &compressed_point, ctx) {
      Ok(point) => return point,
      Err(_) => (),
    };
  }

  panic!("No point found");
}
