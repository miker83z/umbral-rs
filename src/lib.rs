use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroup, EcKey, EcPoint, PointConversionForm};
use openssl::error::ErrorStack;
use openssl::nid::Nid;

use crypto_api_blake2::{Blake2Error, Blake2b};
use orion::aead;
use orion::errors::UnknownCryptoError;

//#[derive(Debug)]
pub struct PublicKey {
    point: EcPoint,
}

//#[derive(Debug)]
pub struct PrivateKey {
    num: BigNum,
}

//#[derive(Debug)]
pub struct Capsule {
    /// public key corresponding to private key used to encrypt the temp key.
    e_point: PublicKey,
    /// public key corresponding to private key used to encrypt the temp key.
    v_point: PublicKey,
    sign: BigNum,
}

fn _hash_to_curvebn(mut bytes: Vec<u8>, group: &EcGroup) -> BigNum {
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

fn _encapsulate(from_public_key: &PublicKey, group: &EcGroup) -> (Vec<u8>, Capsule) {
    // BN context needed for the heap
    let mut ctx = BigNumContext::new().unwrap();

    // R point generation
    let r_key = EcKey::generate(group).unwrap();
    let mut r_point = EcPoint::new(group).unwrap();
    r_point
        .mul_generator(group, r_key.private_key(), &ctx)
        .unwrap();
    let mut to_hash = r_point
        .to_bytes(group, PointConversionForm::COMPRESSED, &mut ctx)
        .unwrap();
    let r_pub_key = PublicKey { point: r_point };

    // U point generation
    let u_key = EcKey::generate(group).unwrap();
    let mut u_point = EcPoint::new(group).unwrap();
    u_point
        .mul_generator(group, u_key.private_key(), &ctx)
        .unwrap();
    let mut to_append = u_point
        .to_bytes(group, PointConversionForm::COMPRESSED, &mut ctx)
        .unwrap();
    to_hash.append(&mut to_append);
    let u_pub_key = PublicKey { point: u_point };

    // Get group order
    let mut order = BigNum::new().unwrap();
    group.order(&mut order, &mut ctx).unwrap();

    // Get sign
    let h = _hash_to_curvebn(to_hash, group);
    let mut mul_point = BigNum::new().unwrap();
    mul_point.mod_mul(&r_key.private_key(), &h, &order, &mut ctx);
    let mut s = BigNum::new().unwrap();
    s.mod_add(u_key.private_key(), &mul_point, &order, &mut ctx);

    // Base key generation i.e. mul of a BNs sum
    // Sum R and U points
    let mut sum = BigNum::new().unwrap();
    sum.mod_add(r_key.private_key(), u_key.private_key(), &order, &mut ctx);
    // Multiply previous sum with from_public_key
    let mut base_key_point = EcPoint::new(group).unwrap();
    base_key_point
        .mul(group, &from_public_key.point, &sum, &ctx)
        .unwrap();
    let base_key = base_key_point
        .to_bytes(group, PointConversionForm::COMPRESSED, &mut ctx)
        .unwrap();

    // KDF
    let mut buf = vec![0; 32];
    let kdf = Blake2b::kdf();
    let salt = vec![0; 16]; //TODO
    let info = vec![0; 16]; //TODO
    kdf.derive(&mut buf, &base_key, &salt, &info).unwrap();

    (
        buf,
        Capsule {
            e_point: r_pub_key,
            v_point: u_pub_key,
            sign: s,
        },
    )
}

pub fn encrypt(
    from_public_key: &PublicKey,
    plaintext_b: &[u8],
    group: &EcGroup,
) -> (Vec<u8>, Capsule) {
    let (key, capsule) = _encapsulate(&from_public_key, &group);

    // DEM
    // TODO Authenticated data
    let secret_key = aead::SecretKey::from_slice(&key).unwrap();
    let ciphertext = aead::seal(&secret_key, plaintext_b).expect("Sync enc error");
    ////let decrypted_data = aead::open(&secret_key, &ciphertext).expect("Sync dec error");

    (ciphertext, capsule)
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::ec::{EcGroup, EcKey, EcPoint};

    #[test]
    fn encrypt_simple() {
        let group = EcGroup::from_curve_name(Nid::SECP256K1).expect("Er");
        let key = EcKey::generate(&group).unwrap();
        let pb = key.public_key().to_owned(&group).unwrap();
        let p = PublicKey { point: pb };
        let sc = key.private_key().to_owned().unwrap();
        let s = PrivateKey { num: sc };

        let plaintext = String::from("Hello, umbral!");

        let (cipher, capsule) = encrypt(&p, plaintext.as_bytes(), &group);
        println!("{:?}", cipher);
        //assert_eq!(2 + 2, 4);
    }
}
