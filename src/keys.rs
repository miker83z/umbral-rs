pub use crate::curve::{CurveBN, CurvePoint, Params};

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
      pk: CurvePoint::from_EcPoint(key.public_key(), params),
      sk: CurveBN::from_BigNum(key.private_key(), params),
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
  s: EcdsaSig,
}

impl Signature {
  pub fn from_EcdsaSig(other: &EcdsaSig) -> Self {
    let r_p = other.r().to_owned().expect("Error in Signature clone");
    let s_p = other.s().to_owned().expect("Error in Signature clone");
    Signature {
      s: EcdsaSig::from_private_components(r_p, s_p).unwrap(),
    }
  }

  pub fn to_owned(&self) -> Self {
    let r_p = self.s.r().to_owned().expect("Error in Signature clone");
    let s_p = self.s.s().to_owned().expect("Error in Signature clone");
    Signature {
      s: EcdsaSig::from_private_components(r_p, s_p).unwrap(),
    }
  }

  pub fn verify(&self, data: &Vec<u8>, verifying_pk: &CurvePoint) -> bool {
    let ver_key = EcKey::from_public_key(verifying_pk.params().group(), verifying_pk.point())
      .expect("Error in Key creation");
    self
      .s
      .verify(data, &ver_key)
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
    let pk = CurvePoint::from_EcPoint(key.public_key(), params);
    Signer {
      key: key,
      pk: pk,
      params: Rc::clone(params),
    }
  }

  pub fn sign(&self, data: &Vec<u8>) -> Signature {
    Signature::from_EcdsaSig(&EcdsaSig::sign(data, &self.key).expect("Error in Signer signature"))
  }

  pub fn public_key(&self) -> &CurvePoint {
    &self.pk
  }

  pub fn params(&self) -> &Rc<Params> {
    &self.params
  }
}
