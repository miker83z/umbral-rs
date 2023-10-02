use crate::internal::curve::{CurveBN, CurvePoint, Params};
use crate::internal::errors::PreErrors;
use crate::internal::keys::Signature;
use crate::internal::kfrag::KFrag;
use crate::internal::schemes::{hash_to_curvebn, Blake2bHash, ExtendedKeccak, SHA256Hash};

use std::fmt::Debug;
use std::rc::Rc;

use openssl::bn::{BigNum, BigNumRef};

pub struct Capsule {
    e_point: CurvePoint,
    v_point: CurvePoint,
    sign: CurveBN,
    delegating_key: Option<CurvePoint>,
    receiving_key: Option<CurvePoint>,
    verifying_key: Option<CurvePoint>,
    attached_cfrags: Vec<CFrag>,
}

impl Capsule {
    pub fn new(e: &CurvePoint, v: &CurvePoint, s: &CurveBN) -> Self {
        Capsule {
            e_point: e.to_owned(),
            v_point: v.to_owned(),
            sign: s.to_owned(),
            delegating_key: None,
            receiving_key: None,
            verifying_key: None,
            attached_cfrags: Vec::new(),
        }
    }

    pub fn from_bytes(bytes: &Vec<u8>, params: &Rc<Params>) -> Result<Self, PreErrors> {
        if bytes.len() != Self::expected_bytes_length(params) {
            return Err(PreErrors::InvalidBytes);
        }
        let mut bytes = bytes.clone();
        let bn_size = CurveBN::expected_bytes_length(params);
        let point_size = CurvePoint::expected_bytes_length(params);

        let sign = CurveBN::from_bytes(&bytes.split_off(bytes.len() - bn_size), params)?;
        let v_point = CurvePoint::from_bytes(&bytes.split_off(bytes.len() - point_size), params)?;
        let e_point = CurvePoint::from_bytes(&bytes.split_off(bytes.len() - point_size), params)?;

        Ok(Capsule {
            e_point,
            v_point,
            sign,
            delegating_key: None,
            receiving_key: None,
            verifying_key: None,
            attached_cfrags: Vec::new(),
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.e_point.to_bytes();
        bytes.append(&mut self.v_point.to_bytes());
        bytes.append(&mut self.sign.to_bytes());
        bytes
    }

    pub fn expected_bytes_length(params: &Rc<Params>) -> usize {
        let bn_size = CurveBN::expected_bytes_length(params);
        let point_size = CurvePoint::expected_bytes_length(params);

        // e_point: CurvePoint, --> 1 point_size
        // v_point: CurvePoint, --> 1 point_size
        // sign: BigNum, --> 1 bn_size
        return bn_size + point_size * 2;
    }

    pub fn eq(&self, other: &Capsule) -> bool {
        if self.e_point.eq(&other.e_point)
            && self.v_point.eq(&other.v_point)
            && self.sign.eq(&other.sign)
        {
            return true;
        }
        return false;
    }

    pub fn set_correctness_keys(
        &mut self,
        delegating: &CurvePoint,
        receiving: &CurvePoint,
        verifying: &CurvePoint,
    ) {
        self.delegating_key = Some(delegating.to_owned());
        self.receiving_key = Some(receiving.to_owned());
        self.verifying_key = Some(verifying.to_owned());
    }

    pub fn attach_cfrag(&mut self, cfrag: &CFrag) -> Result<(), PreErrors> {
        // match cfrag.verify_correctness(self) {
        //     Ok(correct) => {
        //         if correct {
        //             self.attached_cfrags.push(cfrag.clone());
        //             return Ok(());
        //         } else {
        //             return Err(PreErrors::InvalidCFrag);
        //         }
        //     }
        //     Err(err) => return Err(err),
        // }
        self.attached_cfrags.push(cfrag.clone());
        return Ok(());
    }

    pub fn delegating_key(&self) -> &Option<CurvePoint> {
        &self.delegating_key
    }

    pub fn receiving_key(&self) -> &Option<CurvePoint> {
        &self.receiving_key
    }

    pub fn verifying_key(&self) -> &Option<CurvePoint> {
        &self.verifying_key
    }

    pub fn verify(&self) -> bool {
        let params = &self.e_point.params();
        let e = &self.e_point;
        let v = &self.v_point;

        let mut to_hash = e.to_bytes();
        to_hash.append(&mut v.to_bytes());
        let h = hash_to_curvebn::<Blake2bHash>(&to_hash, params, None);

        let first = CurvePoint::mul_gen(&self.sign, params);

        let second = v + &(e * &h);

        first.eq(&second)
    }

    pub fn e(&self) -> &CurvePoint {
        &self.e_point
    }

    pub fn v(&self) -> &CurvePoint {
        &self.v_point
    }

    pub fn sign(&self) -> &CurveBN {
        &self.sign
    }

    pub fn attached_cfrags(&self) -> &Vec<CFrag> {
        &self.attached_cfrags
    }
}

pub struct CorrectnessProof {
    e2: CurvePoint,
    v2: CurvePoint,
    u1: CurvePoint,
    u2: CurvePoint,
    z3: CurveBN,
    kfrag_signature: Signature,
    metadata: Option<Vec<u8>>,
}

impl std::fmt::Debug for CorrectnessProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CorrectnessProof")
            .field("e2", &self.e2)
            .field("v2", &self.v2)
            .field("u1", &self.u1)
            .field("u2", &self.u2)
            .field("z3", &self.z3)
            .finish()
    }
}

impl Clone for CorrectnessProof {
    fn clone(&self) -> Self {
        CorrectnessProof {
            e2: self.e2.to_owned(),
            v2: self.v2.to_owned(),
            u1: self.u1.to_owned(),
            u2: self.u2.to_owned(),
            z3: self.z3.to_owned(),
            kfrag_signature: self.kfrag_signature.to_owned(),
            metadata: self.metadata.clone(),
        }
    }
}

impl CorrectnessProof {
    pub fn new(
        point_e2: &CurvePoint,
        point_v2: &CurvePoint,
        point_kfrag_commitment: &CurvePoint,
        point_kfrag_pok: &CurvePoint,
        bn_sig: &CurveBN,
        kfrag_signature: &Signature,
        metadata: Option<Vec<u8>>,
    ) -> Self {
        CorrectnessProof {
            e2: point_e2.to_owned(),
            v2: point_v2.to_owned(),
            u1: point_kfrag_commitment.to_owned(),
            u2: point_kfrag_pok.to_owned(),
            z3: bn_sig.to_owned(),
            kfrag_signature: kfrag_signature.to_owned(),
            metadata,
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

        let kfrag_signature =
            Signature::from_bytes(&bytes.split_off(bytes.len() - signature_size), params)?;
        let z3 = CurveBN::from_bytes(&bytes.split_off(bytes.len() - bn_size), params)?;
        let u2 = CurvePoint::from_bytes(&bytes.split_off(bytes.len() - point_size), params)?;
        let u1 = CurvePoint::from_bytes(&bytes.split_off(bytes.len() - point_size), params)?;
        let v2 = CurvePoint::from_bytes(&bytes.split_off(bytes.len() - point_size), params)?;
        let e2 = CurvePoint::from_bytes(&bytes.split_off(bytes.len() - point_size), params)?;

        Ok(CorrectnessProof {
            e2,
            v2,
            u1,
            u2,
            z3,
            kfrag_signature,
            metadata: None,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.e2.to_bytes();
        bytes.append(&mut self.v2.to_bytes());
        bytes.append(&mut self.u1.to_bytes());
        bytes.append(&mut self.u2.to_bytes());
        bytes.append(&mut self.z3.to_bytes());
        bytes.append(&mut self.kfrag_signature.to_bytes());

        bytes
    }

    pub fn expected_bytes_length(params: &Rc<Params>) -> usize {
        let bn_size = CurveBN::expected_bytes_length(params);
        let point_size = CurvePoint::expected_bytes_length(params);

        //   e2: CurvePoint, --> 1 point_size
        //   v2: CurvePoint, --> 1 point_size
        //   u1: CurvePoint, --> 1 point_size
        //   u2: CurvePoint, --> 1 point_size
        //   z3: CurveBN, --> 1 bn_size
        //   kfrag_signature: Signature, --> 2 bn_size

        return bn_size * 3 + point_size * 4;
    }

    pub fn eq(&self, other: &CorrectnessProof) -> bool {
        if self.e2.eq(&other.e2)
            && self.v2.eq(&other.v2)
            && self.u1.eq(&other.u1)
            && self.u2.eq(&other.u2)
            && self.z3.eq(&other.z3)
            && self.kfrag_signature.eq(&other.kfrag_signature)
        {
            return true;
        }
        return false;
    }
}

// #[derive(Debug)]
pub struct CFrag {
    e_i_point: CurvePoint,
    v_i_point: CurvePoint,
    kfrag_id: BigNum,
    precursor: CurvePoint,
    proof: Option<CorrectnessProof>,
}

impl Clone for CFrag {
    fn clone(&self) -> Self {
        let clone_proof = match &self.proof {
            Some(expr) => Some(expr.clone()),
            None => None,
        };
        CFrag {
            e_i_point: self.e_i_point.to_owned(),
            v_i_point: self.v_i_point.to_owned(),
            kfrag_id: self.kfrag_id.to_owned().unwrap(),
            precursor: self.precursor.to_owned(),
            proof: clone_proof,
        }
    }
}

impl std::fmt::Debug for CFrag {
    // fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    //     // write the struct fields in the desired format
    //     write!(f, "CurveBN {{ bn: {:?}}}", self.bn)
    // }
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "CFrag {{ e_i_point: {:?}, v_i_point: {:?}, kfrag_id: {:?}, precursor: {:?}, proof: {:?} }}",
            self.e_i_point, self.v_i_point, self.kfrag_id, self.precursor, self.proof
        )
    }
}

impl CFrag {
    pub fn new(
        e_i: &CurvePoint,
        v_i: &CurvePoint,
        kfrag_id: &BigNumRef,
        precursor: &CurvePoint,
    ) -> Self {
        CFrag {
            e_i_point: e_i.to_owned(),
            v_i_point: v_i.to_owned(),
            kfrag_id: kfrag_id.to_owned().unwrap(),
            precursor: precursor.to_owned(),
            proof: None,
        }
    }

    pub fn new_with_fake_proof(
        e_i: &CurvePoint,
        v_i: &CurvePoint,
        kfrag_id: &BigNumRef,
        precursor: &CurvePoint,
        proof: &CorrectnessProof,
    ) -> Self {
        CFrag {
            e_i_point: e_i.to_owned(),
            v_i_point: v_i.to_owned(),
            kfrag_id: kfrag_id.to_owned().unwrap(),
            precursor: precursor.to_owned(),
            proof: Some(proof.clone()),
        }
    }

    pub fn from_bytes(bytes: &Vec<u8>, params: &Rc<Params>) -> Result<Self, PreErrors> {
        let mut bytes = bytes.clone();
        let proof_size = CorrectnessProof::expected_bytes_length(params);
        let mut proof = None;

        if bytes.len() == (Self::expected_bytes_length(params) + proof_size) {
            proof = Some(CorrectnessProof::from_bytes(
                &bytes.split_off(bytes.len() - proof_size),
                params,
            )?);
        } else if bytes.len() != Self::expected_bytes_length(params) {
            return Err(PreErrors::InvalidBytes);
        }

        let bn_size = CurveBN::expected_bytes_length(params);
        let point_size = CurvePoint::expected_bytes_length(params);

        let precursor = CurvePoint::from_bytes(&bytes.split_off(bytes.len() - point_size), params)?;
        let kfrag_id = BigNum::from_slice(&bytes.split_off(bytes.len() - bn_size))
            .expect("Error in BN conversion from bytes");
        let v_i_point = CurvePoint::from_bytes(&bytes.split_off(bytes.len() - point_size), params)?;
        let e_i_point = CurvePoint::from_bytes(&bytes.split_off(bytes.len() - point_size), params)?;

        Ok(CFrag {
            e_i_point,
            v_i_point,
            kfrag_id,
            precursor,
            proof,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.e_i_point.to_bytes();
        bytes.append(&mut self.v_i_point.to_bytes());
        bytes.append(&mut self.kfrag_id.to_vec());
        bytes.append(&mut self.precursor.to_bytes());
        match &self.proof {
            Some(p) => bytes.append(&mut p.to_bytes()),
            None => (),
        }

        bytes
    }

    pub fn expected_bytes_length(params: &Rc<Params>) -> usize {
        let bn_size = CurveBN::expected_bytes_length(params);
        let point_size = CurvePoint::expected_bytes_length(params);

        // e_i_point: CurvePoint, --> 1 point_size
        // v_i_point: CurvePoint, --> 1 point_size
        // kfrag_id: BigNum, --> 1 bn_size
        // precursor: CurvePoint, --> 1 point_size

        return bn_size + point_size * 3;
    }

    pub fn eq(&self, other: &CFrag) -> bool {
        if self.e_i_point.eq(&other.e_i_point)
            && self.v_i_point.eq(&other.v_i_point)
            && self.kfrag_id.eq(&other.kfrag_id)
            && self.precursor.eq(&other.precursor)
        {
            return true;
        }
        return false;
    }

    pub fn prove_correctness(
        &mut self,
        capsule: &Capsule,
        kfrag: &KFrag,
        metadata: Option<Vec<u8>>,
    ) -> Result<(), PreErrors> {
        if !capsule.verify() {
            return Err(PreErrors::InvalidCapsule);
        }

        let params = capsule.e().params();

        let rk = kfrag.re_key_share();
        let t = CurveBN::rand_curve_bn(params);

        let e = capsule.e();
        let v = capsule.v();

        let e_1 = &self.e_i_point;
        let v_1 = &self.v_i_point;

        let u = &CurvePoint::from_ec_point(params.u_point(), params);
        let u_1 = kfrag.commitment();

        let e_2 = e * &t;
        let v_2 = v * &t;
        let u_2 = u * &t;

        let mut to_hash = e.to_bytes();
        to_hash.append(&mut e_1.to_bytes());
        to_hash.append(&mut e_2.to_bytes());
        to_hash.append(&mut v.to_bytes());
        to_hash.append(&mut v_1.to_bytes());
        to_hash.append(&mut v_2.to_bytes());
        to_hash.append(&mut u.to_bytes());
        to_hash.append(&mut u_1.to_bytes());
        to_hash.append(&mut u_2.to_bytes());
        match &metadata {
            Some(m) => to_hash.append(&mut m.clone()),
            None => (),
        }

        let h = hash_to_curvebn::<ExtendedKeccak>(&to_hash, params, None);

        let z_3 = &t + &(&h * rk);

        self.proof = Some(CorrectnessProof::new(
            &e_2,
            &v_2,
            &u_1,
            &u_2,
            &z_3,
            kfrag.signature_for_receiver(),
            metadata,
        ));

        return Ok(());
    }

    pub fn verify_correctness(&self, capsule: &Capsule) -> Result<bool, PreErrors> {
        match &self.proof {
            None => return Err(PreErrors::CFragNoProofProvided),
            Some(proof) => {
                let params = capsule.e().params();

                let (delegating_pk, verifying_pk, receiving_pk) = match (
                    capsule.delegating_key(),
                    capsule.verifying_key(),
                    capsule.receiving_key(),
                ) {
                    (Some(d), Some(v), Some(r)) => (d, v, r),
                    _ => return Err(PreErrors::CapsuleNoCorrectnessProvided),
                };

                let e = capsule.e();
                let v = capsule.v();

                let e_1 = &self.e_i_point;
                let v_1 = &self.v_i_point;

                let u = &CurvePoint::from_ec_point(params.u_point(), params);
                let u_1 = &proof.u1;

                let e_2 = &proof.e2;
                let v_2 = &proof.v2;
                let u_2 = &proof.u2;

                let mut to_hash = e.to_bytes();
                to_hash.append(&mut e_1.to_bytes());
                to_hash.append(&mut e_2.to_bytes());
                to_hash.append(&mut v.to_bytes());
                to_hash.append(&mut v_1.to_bytes());
                to_hash.append(&mut v_2.to_bytes());
                to_hash.append(&mut u.to_bytes());
                to_hash.append(&mut u_1.to_bytes());
                to_hash.append(&mut u_2.to_bytes());
                match &proof.metadata {
                    Some(m) => to_hash.append(&mut m.clone()),
                    None => (),
                }
                let h = hash_to_curvebn::<ExtendedKeccak>(&to_hash, params, None);

                let precursor = &self.precursor;
                let kfrag_id = &self.kfrag_id;

                let mut to_hash2 = kfrag_id.to_vec();
                to_hash2.append(&mut delegating_pk.to_bytes());
                to_hash2.append(&mut receiving_pk.to_bytes());
                to_hash2.append(&mut u_1.to_bytes());
                to_hash2.append(&mut precursor.to_bytes());

                // First checking
                if !proof
                    .kfrag_signature
                    .verify::<SHA256Hash>(&to_hash2, verifying_pk)
                {
                    return Ok(false);
                }

                // Second checking
                let z_3 = &proof.z3;
                // z3 * e == e2 + (h * e1)
                let first = e * &z_3;
                let second = e_2 + &(e_1 * &h);
                if !first.eq(&second) {
                    return Ok(false);
                }

                // Third Checking
                // z3 * v == v2 + (h * v1)
                let first = v * &z_3;
                let second = v_2 + &(v_1 * &h);
                if !first.eq(&second) {
                    return Ok(false);
                }

                // Fourth Checking
                // z3 * u == u2 + (h * u1)
                let first = u * &z_3;
                let second = u_2 + &(u_1 * &h);
                if !first.eq(&second) {
                    return Ok(false);
                }

                return Ok(true);
            }
        }
    }

    pub fn precursor(&self) -> &CurvePoint {
        &self.precursor
    }

    pub fn kfrag_id(&self) -> &BigNumRef {
        &self.kfrag_id
    }

    pub fn e_i_point(&self) -> &CurvePoint {
        &self.e_i_point
    }

    pub fn v_i_point(&self) -> &CurvePoint {
        &self.v_i_point
    }

    pub fn proof(&self) -> &Option<CorrectnessProof> {
        &self.proof
    }
}
