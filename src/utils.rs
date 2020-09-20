use crate::curve::CurveBN;
use sha2::{Digest, Sha512};
const DIGEST_LENGTH: usize = 8;

/* Replaces this module
https://github.com/nucypher/constantSorrow/blob/master/constant_sorrow/constants.py*/
pub fn new_constant_sorrow(name: &str) -> Vec<u8> {
  let mut hasher = Sha512::new();
  hasher.update(name);
  hasher.finalize()[..DIGEST_LENGTH].to_vec()
}

pub fn lambda_coeff(id_i: &CurveBN, selected_ids: &Vec<CurveBN>) -> CurveBN {
  if selected_ids.len() < 2 {
    return CurveBN::from_u32(1, id_i.params());
  }

  let mut first = 0;
  if selected_ids[first].eq(id_i) {
    first = 1;
  }

  let mut res = &selected_ids[first] / &(&selected_ids[first] - &id_i);
  first += 1;

  for i in first..selected_ids.len() {
    if !selected_ids[i].eq(id_i) {
      res = &(&res * &selected_ids[i]) / &(&selected_ids[i] - &id_i);
    }
  }

  res
}

pub fn poly_eval(coeffs: &Vec<CurveBN>, x: &CurveBN) -> CurveBN {
  let n = coeffs.len();
  let mut res = coeffs.last().unwrap().to_owned();

  for i in 2..(n + 1) {
    res = &(&res * x) + &coeffs[n - i];
  }

  res
}
