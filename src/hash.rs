use crypto_api_blake2::{Blake2Error, Blake2b};
use openssl::bn::{BigNum, BigNumContext, MsbOption};
use openssl::ec::{EcGroup, EcGroupRef, EcKey, EcPoint, EcPointRef, PointConversionForm};
use openssl::ecdsa::EcdsaSig;
use openssl::nid::Nid;
use openssl::pkey::Private;
use openssl::sha;

pub fn _unsafe_hash_to_point_g(group: &EcGroupRef) -> EcPoint {
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

pub fn _hash_to_curvebn(mut bytes: Vec<u8>, group: &EcGroup) -> BigNum {
  let customization_string = String::from("hash_to_curvebn");
  let mut to_hash = customization_string.into_bytes();
  to_hash.append(&mut bytes);

  // Get the digest
  let hash = Blake2b::hash();
  let mut digest = vec![0; 64];
  hash.hash(&mut digest, &to_hash);
  let digestBN = BigNum::from_slice(&digest).unwrap();

  // Get order minus one
  let mut ctx = BigNumContext::new().unwrap();
  let one = BigNum::from_dec_str("1").unwrap();
  let mut order = BigNum::new().unwrap();
  group.order(&mut order, &mut ctx).unwrap();
  let mut order_minus_one = BigNum::new().unwrap();
  order_minus_one.checked_sub(&order, &one);

  // Compute modulo
  let mut modul = BigNum::new().unwrap();
  modul.checked_rem(&digestBN, &order_minus_one, &mut ctx);

  // To Curve BN
  let mut finalBN = BigNum::new().unwrap();
  finalBN.checked_add(&modul, &one);

  finalBN
}
