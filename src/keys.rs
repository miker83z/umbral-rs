pub use crate::params::Params;

use openssl::bn::{BigNum, BigNumContext, BigNumRef, MsbOption};
use openssl::ec::{EcGroup, EcGroupRef, EcKey, EcKeyRef, EcPoint, EcPointRef, PointConversionForm};
use openssl::nid::Nid;
use openssl::pkey::{Private, Public};

//#[derive(Debug)]
pub struct PublicKey {
  point: EcPoint,
  params: Params,
}

impl PublicKey {
  pub fn from_key(key: &EcKeyRef<Public>) -> Self {
    let group = key.group();
    PublicKey {
      point: key.public_key().to_owned(group).unwrap(),
      params: Params::new(group),
    }
  }

  pub fn from_point(group: &EcGroupRef, point: &EcPointRef) -> Self {
    PublicKey {
      point: point.to_owned(group).unwrap(),
      params: Params::new(group),
    }
  }

  pub fn point(&self) -> &EcPointRef {
    &self.point
  }

  pub fn params(&self) -> &Params {
    &self.params
  }
}

//#[derive(Debug)]
pub struct KeyPair {
  priv_bn: BigNum,
  pub_point: PublicKey,
  params: Params,
}

impl KeyPair {
  pub fn new(group: &EcGroupRef) -> Self {
    let key = EcKey::generate(group).unwrap();
    KeyPair {
      priv_bn: key.private_key().to_owned().unwrap(),
      pub_point: PublicKey::from_point(group, key.public_key()),
      params: Params::new(group),
    }
  }

  pub fn public_key(&self) -> &PublicKey {
    &self.pub_point
  }

  pub fn private_key(&self) -> &BigNumRef {
    &self.priv_bn
  }
}
