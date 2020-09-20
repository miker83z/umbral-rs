use crate::capsule::Capsule;
use crate::curve::{CurveBN, CurvePoint};
use crate::errors::PreErrors;
use crate::keys::Signature;

use openssl::bn::{BigNum, BigNumRef};

#[derive(Copy, Clone)]
pub enum KFragMode {
  NoKey = 0,
  DelegatingOnly = 1,
  ReceivingOnly = 2,
  DelegatingAndReceiving = 3,
}

pub struct KFrag {
  identifier: BigNum,
  re_key_share: CurveBN,
  commitment: CurvePoint,
  precursor: CurvePoint,
  signature_for_proxy: Signature,
  signature_for_receiver: Signature,
  keys_mode_in_signature: KFragMode,
}

impl KFrag {
  pub fn new(
    identifier: &BigNumRef,
    re_key_share: &CurveBN,
    commitment: &CurvePoint,
    precursor: &CurvePoint,
    signature_for_proxy: &Signature,
    signature_for_receiver: &Signature,
    keys_mode_in_signature: KFragMode,
  ) -> Self {
    KFrag {
      identifier: identifier.to_owned().unwrap(),
      re_key_share: re_key_share.to_owned(),
      commitment: commitment.to_owned(),
      precursor: precursor.to_owned(),
      signature_for_proxy: signature_for_proxy.to_owned(),
      signature_for_receiver: signature_for_receiver.to_owned(),
      keys_mode_in_signature,
    }
  }

  pub fn delegating_key_in_signature(&self) -> bool {
    match self.keys_mode_in_signature {
      KFragMode::NoKey => false,
      KFragMode::DelegatingOnly => true,
      KFragMode::ReceivingOnly => false,
      KFragMode::DelegatingAndReceiving => true,
    }
  }

  pub fn receiving_key_in_signature(&self) -> bool {
    match self.keys_mode_in_signature {
      KFragMode::NoKey => false,
      KFragMode::DelegatingOnly => false,
      KFragMode::ReceivingOnly => true,
      KFragMode::DelegatingAndReceiving => true,
    }
  }

  pub fn verify(
    &self,
    verifying_key: &CurvePoint,
    delegating_key: Option<&CurvePoint>,
    receiving_key: Option<&CurvePoint>,
  ) -> Result<bool, PreErrors> {
    let params = self.commitment.params();

    // Some preliminary checkings
    if !verifying_key.params().eq(params) {
      return Err(PreErrors::InvalidProvidedKeys);
    }
    if self.delegating_key_in_signature() {
      match delegating_key {
        Some(key) => {
          if !key.params().eq(params) {
            return Err(PreErrors::InvalidProvidedKeys);
          }
        }
        None => return Err(PreErrors::InvalidProvidedKeys),
      };
    }
    if self.receiving_key_in_signature() {
      match receiving_key {
        Some(key) => {
          if !key.params().eq(params) {
            return Err(PreErrors::InvalidProvidedKeys);
          }
        }
        None => return Err(PreErrors::InvalidProvidedKeys),
      };
    }

    // Verify that the commitment is well-formed
    let commitment_temp = &CurvePoint::from_ec_point(params.u_point(), params) * &self.re_key_share;
    if !commitment_temp.eq(&self.commitment) {
      return Ok(false);
    }

    let mut to_hash = self.identifier.to_vec();
    to_hash.append(&mut self.commitment.to_bytes());
    to_hash.append(&mut self.precursor.to_bytes());

    match self.keys_mode_in_signature {
      KFragMode::DelegatingAndReceiving => {
        to_hash.append(
          &mut (KFragMode::DelegatingAndReceiving as u8)
            .to_ne_bytes()
            .to_vec(),
        );
        to_hash.append(&mut delegating_key.unwrap().to_bytes());
        to_hash.append(&mut receiving_key.unwrap().to_bytes());
      }
      KFragMode::DelegatingOnly => {
        to_hash.append(&mut (KFragMode::DelegatingOnly as u8).to_ne_bytes().to_vec());
        to_hash.append(&mut delegating_key.unwrap().to_bytes());
      }
      KFragMode::ReceivingOnly => {
        to_hash.append(&mut (KFragMode::ReceivingOnly as u8).to_ne_bytes().to_vec());
        to_hash.append(&mut receiving_key.unwrap().to_bytes());
      }
      KFragMode::NoKey => {
        to_hash.append(&mut (KFragMode::NoKey as u8).to_ne_bytes().to_vec());
      }
    }

    Ok(
      self
        .signature_for_proxy
        .verify_sha2(&to_hash, verifying_key),
    )
  }

  pub fn verify_for_capsule(&self, capsule: &Capsule) -> Result<bool, PreErrors> {
    self.verify(
      capsule.verifying_key(),
      Some(capsule.delegating_key()),
      Some(capsule.receiving_key()),
    )
  }

  pub fn re_key_share(&self) -> &CurveBN {
    &self.re_key_share
  }

  pub fn id(&self) -> &BigNumRef {
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
