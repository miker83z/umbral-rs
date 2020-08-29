use openssl::bn::{BigNum, BigNumContext, MsbOption};
use openssl::ec::{EcGroup, EcKey, EcPoint, PointConversionForm};
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

fn _poly_eval(coeffs: &Vec<BigNum>, x: &BigNum, group: &EcGroup) -> BigNum {
    let mut ctx = BigNumContext::new().unwrap();
    let mut order = BigNum::new().unwrap();
    group.order(&mut order, &mut ctx).unwrap();
    let mut res = BigNum::new().unwrap();
    let n = coeffs.len();

    res.checked_add(&BigNum::new().unwrap(), &coeffs[n - 1]);

    for i in 2..(n + 1) {
        let mut tmp_res = BigNum::new().unwrap();
        tmp_res.mod_mul(&res, x, &order, &mut ctx);
        res.mod_add(&tmp_res, &coeffs[n - i], &order, &mut ctx);
    }

    res
}

fn _rand_curve_bn(group: &EcGroup) -> BigNum {
    let mut ctx = BigNumContext::new().unwrap();
    let mut zero = BigNum::new().unwrap();
    let mut order = BigNum::new().unwrap();
    group.order(&mut order, &mut ctx).unwrap();

    let mut rand = BigNum::new().unwrap();
    // Check validity
    loop {
        order.rand_range(&mut rand);
        if rand > zero && rand < order {
            break;
        }
    }

    rand
}

fn _unsafe_hash_to__point_g(group: &EcGroup) -> EcPoint {
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

pub fn generate_kfrags(
    delegating_sk: &PrivateKey,
    receiving_pk: &PublicKey,
    threshold: usize,
    n: usize,
    signer: &PrivateKey,
    group: &EcGroup,
) -> bool {
    if threshold <= 0 || threshold > n {
        println!("Error"); //TODO
    }

    // TODO check curve

    /* The precursor point is used as an ephemeral public key in a DH key exchange,
    and the resulting shared secret 'dh_point' is used to derive other secret values
    */
    let precursor_key = EcKey::generate(&group).unwrap();
    let precursor_pk = precursor_key.public_key().to_owned(&group).unwrap();
    let precursor_sk = precursor_key.private_key().to_owned().unwrap();

    // Multiply precursor with receiving_pk
    let mut ctx = BigNumContext::new().unwrap();
    let mut dh_point = EcPoint::new(group).unwrap();
    dh_point
        .mul(group, &receiving_pk.point, &precursor_sk, &ctx)
        .unwrap();

    // Prepare for hash
    let mut dh = dh_point
        .to_bytes(group, PointConversionForm::COMPRESSED, &mut ctx)
        .unwrap();
    let mut to_hash = precursor_pk
        .to_bytes(group, PointConversionForm::COMPRESSED, &mut ctx)
        .unwrap();
    let mut to_append = receiving_pk
        .point
        .to_bytes(group, PointConversionForm::COMPRESSED, &mut ctx)
        .unwrap();
    to_hash.append(&mut to_append);
    to_hash.append(&mut dh);
    let mut to_hash2 = to_hash.clone();
    //TODO constant hash, constant_sorrow py module
    let constant_string = String::from("NON_INTERACTIVE");
    let mut constant = constant_string.into_bytes();
    to_hash.append(&mut constant);

    // Secret value 'd' allows to make Umbral non-interactive
    let d = _hash_to_curvebn(to_hash, group);

    // Secret sharing
    // Coefficient zero
    let mut order = BigNum::new().unwrap();
    group.order(&mut order, &mut ctx).unwrap();
    let mut d_inverse = BigNum::new().unwrap();
    d_inverse.mod_inverse(&d, &order, &mut ctx);
    let mut coef_zero = BigNum::new().unwrap();
    coef_zero.mod_mul(&delegating_sk.num, &d_inverse, &order, &mut ctx);
    // Coefficients of the generating polynomial
    let mut coefficients: Vec<BigNum> = Vec::with_capacity(threshold);
    coefficients.push(coef_zero);
    for _ in 1..threshold {
        coefficients.push(_rand_curve_bn(group));
    }

    // Kfrags generation
    let order_bytes_size = order.num_bits();
    for _ in 0..n {
        let mut kfrag_id = BigNum::new().unwrap();
        kfrag_id.rand(order_bytes_size, MsbOption::MAYBE_ZERO, false);
        let mut kfrag_id_bytes = kfrag_id.to_vec();

        //TODO constant hash, constant_sorrow py module
        let constant_string_x = String::from("X_COORDINATE");
        let mut constant_x = constant_string_x.into_bytes();
        let mut to_hash_it = to_hash2.clone();
        to_hash_it.append(&mut constant_x);
        to_hash_it.append(&mut kfrag_id_bytes);

        /*
            The index of the re-encryption key share (which in Shamir's Secret
            Sharing corresponds to x in the tuple (x, f(x)), with f being the
            generating polynomial), is used to prevent reconstruction of the
            re-encryption key without Bob's intervention
        */
        let share_index = _hash_to_curvebn(to_hash_it, group);

        /*
            The re-encryption key share is the result of evaluating the generating
            polynomial for the index value
        */
        let rk = _poly_eval(&coefficients, &share_index, &group);

        // TODO move outside
        let u = _unsafe_hash_to__point_g(group);
        let mut commitment_point = EcPoint::new(group).unwrap();
        commitment_point.mul(group, &u, &rk, &ctx).unwrap();
    }

    true
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

    #[test]
    fn poly_eval() {
        let group = EcGroup::from_curve_name(Nid::SECP256K1).expect("Er");
        let mut coefficients: Vec<BigNum> = Vec::with_capacity(5);
        for i in 0..5 {
            coefficients.push(BigNum::from_u32(i + 2).unwrap());
        }
        let x = BigNum::from_u32(2).unwrap();

        let res = _poly_eval(&coefficients, &x, &group);
        assert_eq!(res, BigNum::from_u32(160).unwrap());
    }

    #[test]
    fn kfrags() {
        let group = EcGroup::from_curve_name(Nid::SECP256K1).expect("Er");
        let del_key = EcKey::generate(&group).unwrap();
        let del_pk_point = del_key.public_key().to_owned(&group).unwrap();
        let delegating_pk = PublicKey {
            point: del_pk_point,
        };
        let del_sk_point = del_key.private_key().to_owned().unwrap();
        let delegating_sk = PrivateKey { num: del_sk_point };

        let rec_key = EcKey::generate(&group).unwrap();
        let rec_pk_point = rec_key.public_key().to_owned(&group).unwrap();
        let receiving_pk = PublicKey {
            point: rec_pk_point,
        };
        //let rec_sk = rec_key.private_key().to_owned().unwrap();

        let kfrags = generate_kfrags(&delegating_sk, &receiving_pk, 2, 5, &delegating_sk, &group);
        println!("{:?}", kfrags);
    }
}
