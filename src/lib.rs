#[macro_use]
extern crate quick_error;
mod capsule;
mod errors;
mod hash;
mod keys;
mod params;

pub use crate::capsule::Capsule;
pub use crate::errors::PreErrors;
pub use crate::hash::{_hash_to_curvebn, _unsafe_hash_to_point_g};
pub use crate::keys::{KeyPair, PublicKey};
pub use crate::params::Params;

use openssl::bn::{BigNum, BigNumContext, MsbOption};
use openssl::ec::{EcGroup, EcKey, EcPoint, EcPointRef, PointConversionForm};
use openssl::ecdsa::EcdsaSig;
use openssl::nid::Nid;
use openssl::pkey::Private;
use openssl::sha;

use crypto_api_blake2::{Blake2Error, Blake2b};
use orion::aead;
use orion::errors::UnknownCryptoError;

// TODO move out
static NO_KEY: &[u8; 1] = b"\x00";
static DELEGATING_ONLY: &[u8; 1] = b"\x01";
static RECEIVING_ONLY: &[u8; 1] = b"\x02";
static DELEGATING_AND_RECEIVING: &[u8; 1] = b"\x03";

pub struct KFrag {
    identifier: BigNum,
    re_key_share: BigNum,
    commitment: EcPoint,
    precursor: EcPoint,
    signature_for_proxy: EcdsaSig,
    signature_for_receiver: EcdsaSig,
    keys_mode_in_signature: [u8; 1],
    params: Params,
}

impl KFrag {
    fn verify(
        &self,
        delegating_key: &PublicKey,
        receiving_key: &PublicKey,
        verifying_key: &PublicKey,
    ) -> bool {
        let mut ctx = BigNumContext::new().unwrap();

        //TODO key.params == params

        let group = &EcGroup::from_curve_name(*self.params.curve_name()).expect("Er");

        // Verify commitment
        let mut commitment_temp = EcPoint::new(group).unwrap();
        commitment_temp
            .mul(group, &self.params.u_point(), &self.re_key_share, &ctx)
            .unwrap();

        let correct_comm = commitment_temp
            .eq(group, &self.commitment, &mut ctx)
            .unwrap();

        // Verify signature
        if correct_comm {
            // TODO update mode
            let mode = DELEGATING_AND_RECEIVING;
            // SHA256 digest
            let mut to_hash_it = self.identifier.to_vec();
            let mut commitment_bytes = self
                .commitment
                .to_bytes(group, PointConversionForm::COMPRESSED, &mut ctx)
                .unwrap();
            to_hash_it.append(&mut commitment_bytes);
            let mut precursor_bytes = self
                .precursor
                .to_bytes(group, PointConversionForm::COMPRESSED, &mut ctx)
                .unwrap();
            to_hash_it.append(&mut precursor_bytes);
            to_hash_it.append(&mut mode.to_vec());
            let mut delegating_pk_bytes = delegating_key
                .point()
                .to_bytes(group, PointConversionForm::COMPRESSED, &mut ctx)
                .unwrap();
            to_hash_it.append(&mut delegating_pk_bytes);
            let mut receiving_pk_bytes = receiving_key
                .point()
                .to_bytes(group, PointConversionForm::COMPRESSED, &mut ctx)
                .unwrap();
            to_hash_it.append(&mut receiving_pk_bytes);
            let mut hasher = sha::Sha256::new();
            hasher.update(&to_hash_it);
            let kfrag_validity_message_digest = hasher.finish();

            return self
                .signature_for_proxy
                .verify(
                    &kfrag_validity_message_digest,
                    &EcKey::from_public_key(group, &verifying_key.point()).unwrap(),
                )
                .unwrap();
        } else {
            return false;
        }

        true
    }

    fn verify_for_capsule(&self, capsule: &Capsule) -> bool {
        self.verify(
            capsule.delegating_key(),
            capsule.receiving_key(),
            capsule.verifying_key(),
        )
    }
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
    let r_pub_key = PublicKey::new(group, &r_point);

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
    let u_pub_key = PublicKey::new(group, &u_point);

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
        .mul(group, &from_public_key.point(), &sum, &ctx)
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

    (buf, Capsule::new(r_pub_key, u_pub_key, s, group))
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
    delegating_key: &KeyPair,
    receiving_pk: &PublicKey,
    threshold: usize,
    n: usize,
    signer: &KeyPair,
    group: &EcGroup,
) -> Vec<KFrag> {
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
        .mul(group, &receiving_pk.point(), &precursor_sk, &ctx)
        .unwrap();

    // Prepare for hash
    let mut dh = dh_point
        .to_bytes(group, PointConversionForm::COMPRESSED, &mut ctx)
        .unwrap();
    let mut to_hash = precursor_pk
        .to_bytes(group, PointConversionForm::COMPRESSED, &mut ctx)
        .unwrap();
    let mut to_append = receiving_pk
        .point()
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
    coef_zero.mod_mul(
        &delegating_key.private_key().to_owned().unwrap(),
        &d_inverse,
        &order,
        &mut ctx,
    );
    // Coefficients of the generating polynomial
    let mut coefficients: Vec<BigNum> = Vec::with_capacity(threshold);
    coefficients.push(coef_zero);
    for _ in 1..threshold {
        coefficients.push(_rand_curve_bn(group));
    }

    // Kfrags generation
    let mut kfrags: Vec<KFrag> = Vec::new();
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
        let u = _unsafe_hash_to_point_g(group);
        let mut commitment_point = EcPoint::new(group).unwrap();
        commitment_point.mul(group, &u, &rk, &ctx).unwrap();

        // Signing
        // SHA256 digest
        let mut to_hash_it2 = kfrag_id.to_vec();
        let mut delegating_pk_bytes = delegating_key
            .public_key()
            .to_owned(&group)
            .unwrap()
            .to_bytes(group, PointConversionForm::COMPRESSED, &mut ctx)
            .unwrap();
        to_hash_it2.append(&mut delegating_pk_bytes);
        let mut receiving_pk_bytes = receiving_pk
            .point()
            .to_bytes(group, PointConversionForm::COMPRESSED, &mut ctx)
            .unwrap();
        to_hash_it2.append(&mut receiving_pk_bytes);
        let mut commitment_bytes = commitment_point
            .to_bytes(group, PointConversionForm::COMPRESSED, &mut ctx)
            .unwrap();
        to_hash_it2.append(&mut commitment_bytes);
        let mut precursor_bytes = precursor_pk
            .to_bytes(group, PointConversionForm::COMPRESSED, &mut ctx)
            .unwrap();
        to_hash_it2.append(&mut precursor_bytes);
        let mut hasher = sha::Sha256::new();
        hasher.update(&to_hash_it2);
        let validity_message_for_receiver_digest = hasher.finish();
        let signature_for_receiver =
            EcdsaSig::sign(&validity_message_for_receiver_digest, signer).unwrap();

        // TODO update mode
        let mut mode = DELEGATING_AND_RECEIVING;
        // SHA256 digest
        let mut to_hash_it3 = kfrag_id.to_vec();
        let mut commitment_bytes = commitment_point
            .to_bytes(group, PointConversionForm::COMPRESSED, &mut ctx)
            .unwrap();
        to_hash_it3.append(&mut commitment_bytes);
        let mut precursor_bytes = precursor_pk
            .to_bytes(group, PointConversionForm::COMPRESSED, &mut ctx)
            .unwrap();
        to_hash_it3.append(&mut precursor_bytes);
        to_hash_it3.append(&mut mode.to_vec());
        let mut delegating_pk_bytes = delegating_key
            .public_key()
            .to_owned(&group)
            .unwrap()
            .to_bytes(group, PointConversionForm::COMPRESSED, &mut ctx)
            .unwrap();
        to_hash_it3.append(&mut delegating_pk_bytes);
        let mut receiving_pk_bytes = receiving_pk
            .point()
            .to_bytes(group, PointConversionForm::COMPRESSED, &mut ctx)
            .unwrap();
        to_hash_it3.append(&mut receiving_pk_bytes);
        let mut hasher = sha::Sha256::new();
        hasher.update(&to_hash_it3);
        let validity_message_for_proxy_digest = hasher.finish();
        let signature_for_proxy =
            EcdsaSig::sign(&validity_message_for_proxy_digest, signer).unwrap();

        let precursor_pk_it = precursor_pk.to_owned(group).unwrap();
        kfrags.push(KFrag {
            identifier: kfrag_id,
            re_key_share: rk,
            commitment: commitment_point,
            precursor: precursor_pk_it,
            signature_for_proxy: signature_for_proxy,
            signature_for_receiver: signature_for_receiver,
            keys_mode_in_signature: mode.clone(),
            params: Params::new(group),
        });
    }

    kfrags
}

pub fn reencrypt(kfrag: &KFrag, capsule: &Capsule, group: &EcGroup) -> Result<bool, PreErrors> {
    // TODO split
    if !capsule.verify(group) {
        if !kfrag.verify_for_capsule(capsule) {
            println!("WEeeeeee");
            Ok(true)?;
        } else {
            println!("WEeeeeee2");
            Err(PreErrors::InvalidKFrag)?;
        }
        println!("WEeeeeee3");
        Ok(true)
    } else {
        println!("WEeeeeee4");
        Err(PreErrors::InvalidCapsule)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::PreErrors;
    use openssl::ec::{EcGroup, EcKey, EcPoint};

    #[test]
    fn encrypt_simple() {
        let (group, alice, signer, bob_pk) = _generate_credentials();

        let carl = KeyPair::new(&group);
        let carl_pk = carl.public_key();

        // encrypt
        let plaintext = String::from("Hello, umbral!");
        let (cipher, mut capsule) = encrypt(&alice.public_key(), plaintext.as_bytes(), &group);
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
        let (group, alice, signer, bob_pk) = _generate_credentials();

        let carl = KeyPair::new(&group);
        let carl_pk = carl.public_key();

        // encrypt
        let plaintext = String::from("Hello, umbral!");
        let (cipher, mut capsule) = encrypt(&alice.public_key(), plaintext.as_bytes(), &group);

        // keyfrags
        let kfrags = generate_kfrags(&alice, &carl_pk, 2, 5, &signer, &group);
        //println!("{:?}", kfrags);
    }

    #[test]
    fn false_verify_calsule() {
        let (group, alice, signer, bob_pk) = _generate_credentials();

        let carl = KeyPair::new(&group);
        let carl_pk = carl.public_key();

        // encrypt
        let plaintext = String::from("Hello, umbral!");
        let (cipher, mut capsule) = encrypt(&alice.public_key(), plaintext.as_bytes(), &group);

        // keyfrags
        let kfrags = generate_kfrags(&alice, &carl_pk, 2, 5, &signer, &group);

        //set correctness keys
        capsule.set_correctness_keys(&alice.public_key(), &bob_pk, &signer.public_key(), &group);

        //reencrypt
        let r = reencrypt(&kfrags[0], &capsule, &group);
        assert_eq!(PreErrors::InvalidCapsule, r.unwrap_err());
    }

    #[test]
    fn false_verify_kfrag() {
        let (group, alice, signer, bob_pk) = _generate_credentials();

        let carl = KeyPair::new(&group);
        let carl_pk = carl.public_key();

        // encrypt
        let plaintext = String::from("Hello, umbral!");
        let (cipher, mut capsule) = encrypt(&alice.public_key(), plaintext.as_bytes(), &group);

        // keyfrags
        let kfrags = generate_kfrags(&alice, &bob_pk, 2, 5, &signer, &group);

        //set correctness keys
        capsule.set_correctness_keys(&alice.public_key(), &carl_pk, &signer.public_key(), &group);

        let mut res = false;
        for kfrag in kfrags {
            res = res && kfrag.verify_for_capsule(&capsule)
        }

        assert_eq!(res, false);
    }

    #[test]
    fn reencrypt_simple() {
        let (group, alice, signer, bob_pk) = _generate_credentials();

        let plaintext = String::from("Hello, umbral!");

        let (cipher, mut capsule) = encrypt(&alice.public_key(), plaintext.as_bytes(), &group);

        let kfrags = generate_kfrags(&alice, &bob_pk, 2, 5, &signer, &group);

        //set correctness keys
        capsule.set_correctness_keys(&alice.public_key(), &bob_pk, &signer.public_key(), &group);

        //reencrypt
        let r = reencrypt(&kfrags[0], &capsule, &group);
        assert_eq!(r.is_ok(), true);
    }

    fn _generate_credentials() -> (EcGroup, KeyPair, KeyPair, PublicKey) {
        let group = EcGroup::from_curve_name(Nid::SECP256K1).expect("Er");

        let alice = KeyPair::new(&group);
        let signer = KeyPair::new(&group);

        let bob = KeyPair::new(&group);

        (group, alice, signer, *bob.public_key())
    }
}
