pub use crate::hash::_hash_to_curvebn;
pub use crate::keys::{KeyPair, PublicKey};
pub use crate::params::Params;
use openssl::bn::{BigNum, BigNumContext, MsbOption};
use openssl::ec::{EcGroup, EcGroupRef, EcKey, EcPoint, EcPointRef, PointConversionForm};

pub struct Capsule {
  /// public key corresponding to private key used to encrypt the temp key.
  e_point: PublicKey,
  /// public key corresponding to private key used to encrypt the temp key.
  v_point: PublicKey,
  sign: BigNum,
  delegating_key: Option<PublicKey>,
  receiving_key: Option<PublicKey>,
  verifying_key: Option<PublicKey>,
  params: Params,
}

impl Capsule {
  pub fn new(e: &PublicKey, v: &PublicKey, s: &BigNum, group: &EcGroupRef) -> Self {
    Capsule {
      e_point: PublicKey::from_point(group, e.point()),
      v_point: PublicKey::from_point(group, v.point()),
      sign: *s.to_owned(),
      delegating_key: None,
      receiving_key: None,
      verifying_key: None,
      params: Params::new(group),
    }
  }

  // TODO return result
  pub fn set_correctness_keys(
    &mut self,
    delegating: &PublicKey,
    receiving: &PublicKey,
    verifying: &PublicKey,
    group: &EcGroup,
  ) {
    // TODO remove group
    self.delegating_key = Some(PublicKey::from_point(group, delegating.point()));
    self.receiving_key = Some(PublicKey::from_point(group, receiving.point()));
    self.verifying_key = Some(PublicKey::from_point(group, verifying.point()));
  }

  pub fn delegating_key(&self) -> &PublicKey {
    &self.delegating_key.as_ref().unwrap()
  }

  pub fn receiving_key(&self) -> &PublicKey {
    &self.receiving_key.as_ref().unwrap()
  }

  pub fn verifying_key(&self) -> &PublicKey {
    &self.verifying_key.as_ref().unwrap()
  }

  pub fn verify(&self) -> bool {
    let mut ctx = BigNumContext::new().unwrap();
    let group = EcGroup::from_curve_name(*self.params.curve_name()).unwrap();
    let e = self.e_point.point();
    let v = self.v_point.point();
    let mut to_hash = e
      .to_bytes(&group, PointConversionForm::COMPRESSED, &mut ctx)
      .unwrap();
    let mut to_append = v
      .to_bytes(&group, PointConversionForm::COMPRESSED, &mut ctx)
      .unwrap();
    to_hash.append(&mut to_append);
    let h = _hash_to_curvebn(to_hash, &group);
    let mut first = EcPoint::new(&group).unwrap();
    first.mul_generator(&group, &self.sign, &ctx).unwrap();
    let mut mul_point = EcPoint::new(&group).unwrap();
    mul_point.mul(&group, &e, &h, &mut ctx);
    let mut second = EcPoint::new(&group).unwrap();
    second.add(&group, &v, &mul_point, &mut ctx);
    first.eq(&group, &second, &mut ctx).unwrap()
  }
}
