use crate::capsule::Capsule;
use crate::curve::{CurveBN, CurvePoint, Params};
use crate::errors::PreErrors;
use crate::keys::{KeyPair, Signature, Signer};
use crate::schemes::SHA256Hash;

// TODO ?
pub static NO_KEY: &[u8; 1] = b"\x00";
pub static DELEGATING_ONLY: &[u8; 1] = b"\x01";
pub static RECEIVING_ONLY: &[u8; 1] = b"\x02";
pub static DELEGATING_AND_RECEIVING: &[u8; 1] = b"\x03";

pub struct KFrag {
  identifier: CurveBN,
  re_key_share: CurveBN,
  commitment: CurvePoint,
  precursor: CurvePoint,
  signature_for_proxy: Signature,
  signature_for_receiver: Signature,
  keys_mode_in_signature: [u8; 1],
}

impl KFrag {
  pub fn new(
    identifier: &CurveBN,
    re_key_share: &CurveBN,
    commitment: &CurvePoint,
    precursor: &CurvePoint,
    signature_for_proxy: &Signature,
    signature_for_receiver: &Signature,
    keys_mode_in_signature: &[u8; 1],
  ) -> Self {
    KFrag {
      identifier: identifier.to_owned(),
      re_key_share: re_key_share.to_owned(),
      commitment: commitment.to_owned(),
      precursor: precursor.to_owned(),
      signature_for_proxy: signature_for_proxy.to_owned(),
      signature_for_receiver: signature_for_receiver.to_owned(),
      keys_mode_in_signature: keys_mode_in_signature.clone(), //TODO enum
    }
  }

  pub fn verify(
    &self,
    delegating_key: &CurvePoint,
    receiving_key: &CurvePoint,
    verifying_key: &CurvePoint,
  ) -> bool {
    let params = self.identifier.params();

    //TODO key.params == params

    // Verify commitment

    let commitment_temp = &CurvePoint::from_EcPoint(params.u_point(), params) * &self.re_key_share;

    // Verify signature
    if !commitment_temp.eq(&self.commitment) {
      return false;
    } else {
      // TODO update mode
      let mode = DELEGATING_AND_RECEIVING;
      // SHA256 digest
      let mut to_hash = self.identifier.to_bytes();
      to_hash.append(&mut self.commitment.to_bytes());
      to_hash.append(&mut self.precursor.to_bytes());
      to_hash.append(&mut mode.to_vec());
      to_hash.append(&mut delegating_key.to_bytes());
      to_hash.append(&mut receiving_key.to_bytes());

      return self
        .signature_for_proxy
        .verify::<SHA256Hash>(&to_hash, verifying_key);
    }
  }

  pub fn verify_for_capsule(&self, capsule: &Capsule) -> bool {
    self.verify(
      capsule.delegating_key(),
      capsule.receiving_key(),
      capsule.verifying_key(),
    )
  }

  pub fn re_key_share(&self) -> &CurveBN {
    &self.re_key_share
  }

  pub fn id(&self) -> &CurveBN {
    &self.identifier
  }

  pub fn precursor(&self) -> &CurvePoint {
    &self.precursor
  }

  pub fn commitment(&self) -> &CurvePoint {
    &self.commitment
  }

  pub fn signature_for_receiver(&self) -> &Signature {
    &self.signature_for_receiver
  }
}
