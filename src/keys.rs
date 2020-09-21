pub use crate::curve::{CurveBN, CurvePoint, Params};
use crate::errors::PreErrors;
pub use crate::schemes::{Hash, SHA256Hash};

use std::rc::Rc;

use openssl::ec::EcKey;
use openssl::ecdsa::EcdsaSig;
use openssl::pkey::Private;

//#[derive(Debug)]
pub struct KeyPair {
  pk: CurvePoint,
  sk: CurveBN,
}

impl KeyPair {
  pub fn new(params: &Rc<Params>) -> Self {
    let key = EcKey::generate(params.group()).expect("Error in KeyPair creation");
    KeyPair {
      pk: CurvePoint::from_ec_point(key.public_key(), params),
      sk: CurveBN::from_big_num(key.private_key(), params),
    }
  }

  pub fn public_key(&self) -> &CurvePoint {
    &self.pk
  }

  pub fn private_key(&self) -> &CurveBN {
    &self.sk
  }
}

pub struct Signature {
  r: CurveBN,
  s: CurveBN,
}

impl Signature {
  pub fn from_ecdsa_sig(other: &EcdsaSig, params: &Rc<Params>) -> Self {
    let r_p = other.r().to_owned().expect("Error in Signature clone");
    let s_p = other.s().to_owned().expect("Error in Signature clone");
    Signature {
      r: CurveBN::from_big_num(&r_p, params),
      s: CurveBN::from_big_num(&s_p, params),
    }
  }

  pub fn from_bytes(bytes: &Vec<u8>, params: &Rc<Params>) -> Result<Self, PreErrors> {
    if bytes.len() != Self::expected_bytes_length(params) {
      return Err(PreErrors::InvalidBytes);
    }
    let r = CurveBN::from_bytes(&bytes[..bytes.len() / 2].to_vec(), params)?;
    let s = CurveBN::from_bytes(&bytes[bytes.len() / 2..].to_vec(), params)?;
    Ok(Signature { r, s })
  }

  pub fn to_bytes(&self) -> Vec<u8> {
    let mut left = self.r.to_bytes();
    let mut right = self.s.to_bytes();
    left.append(&mut right);
    left
  }

  pub fn expected_bytes_length(params: &Rc<Params>) -> usize {
    2 * params.group_order_size_in_bytes()
  }

  pub fn to_owned(&self) -> Self {
    Signature {
      r: self.r.to_owned(),
      s: self.s.to_owned(),
    }
  }

  pub fn eq(&self, other: &Signature) -> bool {
    if self.r.eq(&other.r) && self.s.eq(&other.s) {
      return true;
    }
    return false;
  }

  pub fn verify_sha2(&self, data: &Vec<u8>, verifying_pk: &CurvePoint) -> bool {
    self.verify::<SHA256Hash>(data, verifying_pk)
  }

  pub fn verify<H>(&self, data: &Vec<u8>, verifying_pk: &CurvePoint) -> bool
  where
    H: Hash,
  {
    let mut hash = H::new(&b"".to_vec());
    hash.update(data);
    let digest = &hash.finalize();
    let ver_key = EcKey::from_public_key(verifying_pk.params().group(), verifying_pk.point())
      .expect("Error in Key creation");
    EcdsaSig::from_private_components(
      self.r.bn().to_owned().unwrap(),
      self.s.bn().to_owned().unwrap(),
    )
    .unwrap()
    .verify(digest, &ver_key)
    .expect("Error in Signature verification")
  }
}

pub struct Signer {
  key: EcKey<Private>,
  pk: CurvePoint,
  params: Rc<Params>,
}

impl Signer {
  pub fn new(params: &Rc<Params>) -> Self {
    let key = EcKey::generate(params.group()).expect("Error in Signer creation");
    let pk = CurvePoint::from_ec_point(key.public_key(), params);
    Signer {
      key: key,
      pk: pk,
      params: Rc::clone(params),
    }
  }

  pub fn sign_sha2(&self, data: &Vec<u8>) -> Signature {
    self.sign::<SHA256Hash>(data)
  }

  pub fn sign<H>(&self, data: &Vec<u8>) -> Signature
  where
    H: Hash,
  {
    let mut hash = H::new(&b"".to_vec());
    hash.update(data);
    let digest = &hash.finalize();
    Signature::from_ecdsa_sig(
      &EcdsaSig::sign(digest, &self.key).expect("Error in Signer signature"),
      &self.params,
    )
  }

  pub fn public_key(&self) -> &CurvePoint {
    &self.pk
  }

  pub fn params(&self) -> &Rc<Params> {
    &self.params
  }
}
