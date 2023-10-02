use crate::internal::capsule::Capsule;
use crate::internal::curve::{CurveBN, CurvePoint, Params};
use crate::internal::errors::PreErrors;
use crate::internal::keys::Signature;

use std::rc::Rc;

use openssl::bn::{BigNum, BigNumRef};

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum KFragMode {
    NoKey = 0,
    DelegatingOnly = 1,
    ReceivingOnly = 2,
    DelegatingAndReceiving = 3,
}

impl KFragMode {
    pub fn from_u8(value: u8) -> Result<Self, PreErrors> {
        match value {
            0 => Ok(KFragMode::NoKey),
            1 => Ok(KFragMode::DelegatingOnly),
            2 => Ok(KFragMode::ReceivingOnly),
            3 => Ok(KFragMode::DelegatingAndReceiving),
            _ => Err(PreErrors::InvalidBytes),
        }
    }
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

    pub fn from_bytes(bytes: &Vec<u8>, params: &Rc<Params>) -> Result<Self, PreErrors> {
        if bytes.len() != Self::expected_bytes_length(params) {
            return Err(PreErrors::InvalidBytes);
        }
        let mut bytes = bytes.clone();
        let bn_size = CurveBN::expected_bytes_length(params);
        let point_size = CurvePoint::expected_bytes_length(params);
        let signature_size = Signature::expected_bytes_length(params);

        let signature_for_receiver =
            Signature::from_bytes(&bytes.split_off(bytes.len() - signature_size), params)?;
        let signature_for_proxy =
            Signature::from_bytes(&bytes.split_off(bytes.len() - signature_size), params)?;
        let keys_mode_in_signature = KFragMode::from_u8(bytes.pop().unwrap())?;
        let precursor = CurvePoint::from_bytes(&bytes.split_off(bytes.len() - point_size), params)?;
        let commitment =
            CurvePoint::from_bytes(&bytes.split_off(bytes.len() - point_size), params)?;
        let re_key_share = CurveBN::from_bytes(&bytes.split_off(bytes.len() - bn_size), params)?;
        let identifier = BigNum::from_slice(&bytes).expect("Error in BN conversion from bytes");

        Ok(KFrag {
            identifier,
            re_key_share,
            commitment,
            precursor,
            signature_for_proxy,
            signature_for_receiver,
            keys_mode_in_signature,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.identifier.to_vec();
        bytes.append(&mut self.re_key_share.to_bytes());
        bytes.append(&mut self.commitment.to_bytes());
        bytes.append(&mut self.precursor.to_bytes());
        bytes.append(&mut (self.keys_mode_in_signature as u8).to_ne_bytes().to_vec());
        bytes.append(&mut self.signature_for_proxy.to_bytes());
        bytes.append(&mut self.signature_for_receiver.to_bytes());

        bytes
    }

    pub fn expected_bytes_length(params: &Rc<Params>) -> usize {
        let bn_size = CurveBN::expected_bytes_length(params);
        let point_size = CurvePoint::expected_bytes_length(params);

        // identifier: BigNum --> 1 bn_size
        // re_key_share: CurveBN --> 1 bn_size
        // commitment: CurvePoint --> 1 point_size
        // precursor: CurvePoint --> 1 point_size
        // signature_for_proxy: Signature --> 2 bn_size
        // signature_for_receiver: Signature --> 2 bn_size
        // keys_mode_in_signature: KFragMode --> 1

        return bn_size * 6 + point_size * 2 + 1;
    }

    pub fn eq(&self, other: &KFrag) -> bool {
        if self.identifier.eq(&other.identifier)
            && self.re_key_share.eq(&other.re_key_share)
            && self.commitment.eq(&other.commitment)
            && self.precursor.eq(&other.precursor)
            && self.signature_for_proxy.eq(&other.signature_for_proxy)
            && self
                .signature_for_receiver
                .eq(&other.signature_for_receiver)
            && self
                .keys_mode_in_signature
                .eq(&other.keys_mode_in_signature)
        {
            return true;
        }
        return false;
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
        let commitment_temp =
            &CurvePoint::from_ec_point(params.u_point(), params) * &self.re_key_share;
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

        Ok(self
            .signature_for_proxy
            .verify_sha2(&to_hash, verifying_key))
    }

    pub fn verify_for_capsule(&self, capsule: &Capsule) -> Result<bool, PreErrors> {
        let (delegating_pk, verifying_pk, receiving_pk) = match (
            capsule.delegating_key(),
            capsule.verifying_key(),
            capsule.receiving_key(),
        ) {
            (Some(d), Some(v), Some(r)) => (d, v, r),
            _ => return Err(PreErrors::CapsuleNoCorrectnessProvided),
        };
        self.verify(verifying_pk, Some(delegating_pk), Some(receiving_pk))
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

    pub fn signature_for_proxy(&self) -> &Signature {
        &self.signature_for_proxy
    }

    pub fn keys_mode_in_signature(&self) -> KFragMode {
        self.keys_mode_in_signature
    }
}
