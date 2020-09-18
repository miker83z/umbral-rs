pub use crate::curve::{CurveBN, CurvePoint, Params};

use std::rc::Rc;

use crypto_api_blake2::Blake2b;
use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroupRef, EcPoint, PointConversionForm};

pub fn unsafe_hash_to_point(group: &EcGroupRef) -> EcPoint {
  let mut ctx = BigNumContext::new().unwrap();

  // TODO parameterize label
  let label_string = String::from("NuCypher/UmbralParameters/u");
  let mut label_bytes = label_string.into_bytes();
  let mut to_hash = label_bytes.len().to_be_bytes().to_vec();

  // Generator
  let generator = group.generator();
  let mut generator_bytes = generator
    .to_bytes(group, PointConversionForm::COMPRESSED, &mut ctx)
    .unwrap();
  let mut generator_len = generator_bytes.len().to_be_bytes().to_vec();

  // Compose data to hash
  to_hash.append(&mut label_bytes);
  to_hash.append(&mut generator_len);
  to_hash.append(&mut generator_bytes);
  let to_hash2 = to_hash.clone();

  // TODO to move out
  let curve_key_size_bytes = (((group.degree() as f64) + 7.0) / 8.0).floor() as usize;

  let mut iterator: usize = 0;
  while iterator < 2usize.pow(32) {
    let mut ibites = iterator.to_be_bytes().to_vec();
    let mut to_hash_it = to_hash2.clone();
    to_hash_it.append(&mut ibites);

    let hash = Blake2b::hash();
    let mut digest = vec![0; 64];
    hash.hash(&mut digest, &to_hash_it);

    let mut sign = String::from("\x02");
    if digest[0] & 1 == 1 {
      sign = String::from("\x03");
    }
    let mut compressed_point = sign.into_bytes();
    compressed_point.append(&mut digest[1..(curve_key_size_bytes + 1)].to_vec());

    match EcPoint::from_bytes(group, &compressed_point, &mut ctx) {
      Ok(point) => return point,
      Err(_) => (),
    };

    iterator += 1;
  }

  panic!("No point found");
}

pub fn hash_to_curvebn(mut bytes: Vec<u8>, params: &Rc<Params>) -> CurveBN {
  let customization_string = String::from("hash_to_curvebn");
  let mut to_hash = customization_string.into_bytes();
  to_hash.append(&mut bytes);

  // Get the digest
  let hash = Blake2b::hash();
  let mut digest = vec![0; 64];
  hash.hash(&mut digest, &to_hash);

  let digestBN = CurveBN::from_slice(&digest, params);

  // Get order minus one
  let one = BigNum::from_dec_str("1").expect("Error in BN creation");
  let order = params.order();
  let mut order_minus_one = BigNum::new().expect("Error in BN creation");
  order_minus_one.checked_sub(&order, &one);

  // Compute modulo
  let mut modul = BigNum::new().expect("Error in BN creation");
  modul.checked_rem(
    &digestBN.bn(),
    &order_minus_one,
    &mut params.ctx().borrow_mut(),
  );

  // To CurveBN
  let mut finalBN = BigNum::new().expect("Error in BN creation");
  finalBN.checked_add(&modul, &one);

  CurveBN::from_BigNum(&finalBN, params)
}
