use crate::curve::{CurveBN, CurvePoint};
use crate::errors::PreErrors;
use crate::keys::Signature;
use crate::kfrag::KFrag;
use crate::schemes::{hash_to_curvebn, Blake2bHash, ExtendedKeccak, SHA256Hash};

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

  // TODO return result
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
    match cfrag.verify_correctness(self) {
      Ok(correct) => {
        if correct {
          self.attached_cfrags.push(cfrag.clone());
          return Ok(());
        } else {
          return Err(PreErrors::InvalidCFrag);
        }
      }
      Err(err) => return Err(err),
    }
  }

  pub fn delegating_key(&self) -> &CurvePoint {
    &self.delegating_key.as_ref().unwrap()
  }

  pub fn receiving_key(&self) -> &CurvePoint {
    &self.receiving_key.as_ref().unwrap()
  }

  pub fn verifying_key(&self) -> &CurvePoint {
    &self.verifying_key.as_ref().unwrap()
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
}

impl CorrectnessProof {
  pub fn new(
    point_e2: &CurvePoint,
    point_v2: &CurvePoint,
    point_kfrag_commitment: &CurvePoint,
    point_kfrag_pok: &CurvePoint,
    bn_sig: &CurveBN,
    kfrag_signature: &Signature,
  ) -> Self {
    CorrectnessProof {
      e2: point_e2.to_owned(),
      v2: point_v2.to_owned(),
      u1: point_kfrag_commitment.to_owned(),
      u2: point_kfrag_pok.to_owned(),
      z3: bn_sig.to_owned(),
      kfrag_signature: kfrag_signature.to_owned(),
    }
  }

  //TODO as trait
  pub fn clone(&self) -> Self {
    CorrectnessProof {
      e2: self.e2.to_owned(),
      v2: self.v2.to_owned(),
      u1: self.u1.to_owned(),
      u2: self.u2.to_owned(),
      z3: self.z3.to_owned(),
      kfrag_signature: self.kfrag_signature.to_owned(),
    }
  }
}

pub struct CFrag {
  e_i_point: CurvePoint,
  v_i_point: CurvePoint,
  kfrag_id: CurveBN,
  precursor: CurvePoint,
  proof: Option<CorrectnessProof>,
}

impl CFrag {
  pub fn new(
    e_i: &CurvePoint,
    v_i: &CurvePoint,
    kfrag_id: &CurveBN,
    precursor: &CurvePoint,
  ) -> Self {
    CFrag {
      e_i_point: e_i.to_owned(),
      v_i_point: v_i.to_owned(),
      kfrag_id: kfrag_id.to_owned(),
      precursor: precursor.to_owned(),
      proof: None,
    }
  }

  //TODO as trait
  pub fn clone(&self) -> Self {
    let clone_proof = match &self.proof {
      Some(expr) => Some(expr.clone()),
      None => None,
    };
    CFrag {
      e_i_point: self.e_i_point.to_owned(),
      v_i_point: self.v_i_point.to_owned(),
      kfrag_id: self.kfrag_id.to_owned(),
      precursor: self.precursor.to_owned(),
      proof: clone_proof,
    }
  }

  pub fn prove_correctness(&mut self, capsule: &Capsule, kfrag: &KFrag) -> Result<(), PreErrors> {
    if !capsule.verify() {
      return Err(PreErrors::InvalidCapsule);
    } else {
      let params = capsule.e().params();

      let rk = kfrag.re_key_share();
      let t = CurveBN::rand_curve_bn(params);

      let e = capsule.e();
      let v = capsule.v();

      let e_1 = &self.e_i_point;
      let v_1 = &self.v_i_point;

      let u = &CurvePoint::from_EcPoint(params.u_point(), params);
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

      let h = hash_to_curvebn::<ExtendedKeccak>(&to_hash, params, None);

      let z_3 = &t + &(&h * rk);

      self.proof = Some(CorrectnessProof::new(
        &e_2,
        &v_2,
        &u_1,
        &u_2,
        &z_3,
        kfrag.signature_for_receiver(),
      ));

      return Ok(());
    }
  }

  pub fn verify_correctness(&self, capsule: &Capsule) -> Result<bool, PreErrors> {
    match &self.proof {
      None => return Err(PreErrors::CFragNoProofProvided),
      Some(proof) => {
        let params = capsule.e().params();

        let delegating_pk = capsule.delegating_key();
        let verifying_pk = capsule.verifying_key();
        let receiving_pk = capsule.receiving_key();

        let e = capsule.e();
        let v = capsule.v();

        let e_1 = &self.e_i_point;
        let v_1 = &self.v_i_point;

        let u = &CurvePoint::from_EcPoint(params.u_point(), params);
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
        //TODO check metadata
        let h = hash_to_curvebn::<ExtendedKeccak>(&to_hash, params, None);

        let precursor = &self.precursor;
        let kfrag_id = &self.kfrag_id;

        let mut to_hash2 = kfrag_id.to_bytes();
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

  pub fn kfrag_id(&self) -> &CurveBN {
    &self.kfrag_id
  }

  pub fn e_i_point(&self) -> &CurvePoint {
    &self.e_i_point
  }

  pub fn v_i_point(&self) -> &CurvePoint {
    &self.v_i_point
  }
}
