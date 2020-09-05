pub use crate::hash::_unsafe_hash_to_point_g;
use openssl::bn::{BigNum, BigNumContext, MsbOption};
use openssl::ec::{EcGroup, EcGroupRef, EcKey, EcPoint, EcPointRef, PointConversionForm};
use openssl::ecdsa::EcdsaSig;
use openssl::nid::Nid;

pub struct Params {
  curve_name: Nid,
  g_point: EcPoint,
  u_point: EcPoint,
}

impl Params {
  pub fn new(group: &EcGroupRef) -> Self {
    Params {
      curve_name: group.curve_name().unwrap(),
      g_point: group.generator().to_owned(group).unwrap(),
      u_point: _unsafe_hash_to_point_g(group),
    }
  }

  pub fn curve_name(&self) -> &Nid {
    &self.curve_name
  }

  pub fn g_point(&self) -> &EcPoint {
    &self.g_point
  }

  pub fn u_point(&self) -> &EcPoint {
    &self.u_point
  }

  pub fn eq(&self, other: &Params) -> bool {
    self.curve_name.eq(other.curve_name())
  }
}
