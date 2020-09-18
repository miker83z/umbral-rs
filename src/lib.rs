extern crate quick_error;
mod capsule;
mod curve;
mod errors;
mod hash;
mod keys;
mod kfrag;
mod schemes;
mod utils;

pub use crate::capsule::{CFrag, Capsule};
pub use crate::curve::{CurveBN, CurvePoint, Params};
pub use crate::errors::PreErrors;
pub use crate::hash::hash_to_curvebn;
pub use crate::keys::{KeyPair, Signer};
pub use crate::kfrag::KFrag;
pub use crate::schemes::{dem_decrypt, dem_encrypt, kdf, DEM_MIN_SIZE};
pub use crate::utils::{lambda_coeff, poly_eval};

use openssl::bn::{BigNum, MsbOption};
use openssl::sha;

fn _encapsulate(from_public_key: &CurvePoint) -> Result<(Vec<u8>, Capsule), PreErrors> {
    // BN context needed for the heap
    let params = from_public_key.params();

    // R point generation
    let r = KeyPair::new(params);
    let u = KeyPair::new(params);

    // Get sign
    let mut to_hash = r.public_key().to_bytes();
    to_hash.append(&mut u.public_key().to_bytes());
    let h = hash_to_curvebn(to_hash, params);

    let s = u.private_key() + &(r.private_key() * &h);

    let shared_key = from_public_key * &(r.private_key() + u.private_key());

    let encapsulated_key = match kdf(&shared_key.to_bytes()) {
        Ok(key) => key,
        Err(err) => return Err(err),
    };

    Ok((
        encapsulated_key,
        Capsule::new(r.public_key(), u.public_key(), &s),
    ))
}

pub fn encrypt(
    from_public_key: &CurvePoint,
    plaintext: &Vec<u8>,
) -> Result<(Vec<u8>, Capsule), PreErrors> {
    let (key, capsule) = match _encapsulate(&from_public_key) {
        Ok(kc) => kc,
        Err(err) => return Err(err),
    };

    match dem_encrypt(&key, plaintext) {
        Ok(ciphertext) => return Ok((ciphertext, capsule)),
        Err(err) => return Err(err),
    };
}

pub fn generate_kfrags(
    delegating_keypair: &KeyPair,
    receiving_pk: &CurvePoint,
    threshold: usize,
    n: usize,
    signer: &Signer,
) -> Result<Vec<KFrag>, PreErrors> {
    if threshold <= 0 || threshold > n {
        return Err(PreErrors::InvalidKFragThreshold);
    }
    if !(delegating_keypair
        .public_key()
        .params()
        .eq(receiving_pk.params()))
    {
        return Err(PreErrors::KeysParametersNotEq);
    }
    let params = delegating_keypair.public_key().params();

    /* The precursor point is used as an ephemeral public key in a DH key exchange,
    and the resulting shared secret 'dh_point' is used to derive other secret values
    */
    let precursor = KeyPair::new(params);
    // Multiply precursor with receiving_pk to obtain DH point
    let dh_point = receiving_pk * precursor.private_key();

    let mut to_hash = precursor.public_key().to_bytes();
    to_hash.append(&mut receiving_pk.to_bytes());
    to_hash.append(&mut dh_point.to_bytes());
    let to_hash2 = to_hash.clone();
    //TODO constant hash, constant_sorrow py module
    let constant_string = String::from("NON_INTERACTIVE");
    to_hash.append(&mut constant_string.into_bytes());

    // Secret value 'd' allows to make Umbral non-interactive
    let d = hash_to_curvebn(to_hash, params);

    /////////////////
    // Secret sharing

    // Coefficients of the generating polynomial
    let mut coefficients: Vec<CurveBN> = Vec::with_capacity(threshold);
    // Coefficient zero
    let coef_zero = delegating_keypair.private_key() / &d;
    coefficients.push(coef_zero);
    for _ in 1..threshold {
        coefficients.push(CurveBN::rand_curve_bn(params));
    }

    // Kfrags generation
    let mut kfrags: Vec<KFrag> = Vec::new();
    let order_bytes_size = params.order().num_bits();
    for _ in 0..n {
        let mut kfrag_id = BigNum::new().unwrap();
        match kfrag_id.rand(order_bytes_size, MsbOption::MAYBE_ZERO, false) {
            Ok(_) => (),
            Err(err) => {
                println!("BigNum random generation error: {:?}", err);
                return Err(PreErrors::GenericError);
            }
        }
        let kfrag_id = CurveBN::from_BigNum(&kfrag_id, params);

        let mut to_hash_it = to_hash2.clone();
        let constant_string_x = String::from("X_COORDINATE"); //TODO constant hash, constant_sorrow py module
        to_hash_it.append(&mut constant_string_x.into_bytes());
        to_hash_it.append(&mut kfrag_id.to_bytes());

        /*
            The index of the re-encryption key share (which in Shamir's Secret
            Sharing corresponds to x in the tuple (x, f(x)), with f being the
            generating polynomial), is used to prevent reconstruction of the
            re-encryption key without Bob's intervention
        */
        let share_index = hash_to_curvebn(to_hash_it, params);

        /*
            The re-encryption key share is the result of evaluating the generating
            polynomial for the index value
        */
        let rk = poly_eval(&coefficients, &share_index);

        let u = CurvePoint::from_EcPoint(params.u_point(), params);
        let commitment_point = &u * &rk;

        // Signing
        let mut to_hash_it2 = kfrag_id.to_bytes();
        to_hash_it2.append(&mut delegating_keypair.public_key().to_bytes());
        to_hash_it2.append(&mut receiving_pk.to_bytes());
        to_hash_it2.append(&mut commitment_point.to_bytes());
        to_hash_it2.append(&mut precursor.public_key().to_bytes());
        let mut hasher = sha::Sha256::new();
        hasher.update(&to_hash_it2);
        let validity_message_for_receiver_digest = hasher.finish();
        let signature_for_receiver = signer.sign(&validity_message_for_receiver_digest.to_vec());

        // TODO update mode
        let mode = kfrag::DELEGATING_AND_RECEIVING;
        // SHA256 digest
        let mut to_hash_it3 = kfrag_id.to_bytes();
        to_hash_it3.append(&mut commitment_point.to_bytes());
        to_hash_it3.append(&mut precursor.public_key().to_bytes());
        to_hash_it3.append(&mut mode.to_vec());
        to_hash_it3.append(&mut delegating_keypair.public_key().to_bytes());
        to_hash_it3.append(&mut receiving_pk.to_bytes());
        let mut hasher = sha::Sha256::new();
        hasher.update(&to_hash_it3);
        let validity_message_for_proxy_digest = hasher.finish();
        let signature_for_proxy = signer.sign(&validity_message_for_proxy_digest.to_vec());

        kfrags.push(KFrag::new(
            &kfrag_id,
            &rk,
            &commitment_point,
            &precursor.public_key(),
            &signature_for_proxy,
            &signature_for_receiver,
            &mode,
        ));
    }

    Ok(kfrags)
}

pub fn reencrypt(
    kfrag: &KFrag,
    capsule: &Capsule,
    provide_proof: bool,
    verify_kfrag: bool,
) -> Result<CFrag, PreErrors> {
    if !capsule.verify() {
        return Err(PreErrors::InvalidCapsule);
    } else {
        if verify_kfrag && !kfrag.verify_for_capsule(capsule) {
            return Err(PreErrors::InvalidKFrag);
        } else {
            let rk = kfrag.re_key_share();
            let e_i = capsule.e() * rk;
            let v_i = capsule.v() * rk;

            let mut cfrag = CFrag::new(&e_i, &v_i, kfrag.id(), kfrag.precursor());

            if provide_proof {
                match cfrag.prove_correctness(capsule, kfrag) {
                    Ok(_) => (),
                    Err(err) => return Err(err),
                }
            }

            return Ok(cfrag);
        }
    }
}

fn _decapsulate(capsule: &Capsule, receiving: &CurveBN) -> Result<Vec<u8>, PreErrors> {
    if !capsule.verify() {
        return Err(PreErrors::InvalidCapsule);
    } else {
        let shared_key = &(capsule.e() + capsule.v()) * receiving;
        kdf(&shared_key.to_bytes())
    }
}

fn _decapsulate_reencrypted(
    capsule: &Capsule,
    receiver_keypair: &KeyPair,
) -> Result<Vec<u8>, PreErrors> {
    let params = capsule.e().params();

    let pk = receiver_keypair.public_key();
    let sk = receiver_keypair.private_key();

    let precursor = capsule.attached_cfrags()[0].precursor();
    let dh_point = precursor * sk;

    // Combination of CFrags via Shamir's Secret Sharing reconstruction
    let mut xs: Vec<CurveBN> = Vec::new();
    for cfrag in capsule.attached_cfrags() {
        let mut to_hash = precursor.to_bytes();
        to_hash.append(&mut pk.to_bytes());
        to_hash.append(&mut dh_point.to_bytes());
        to_hash.append(&mut String::from("X_COORDINATE").into_bytes());
        to_hash.append(&mut cfrag.kfrag_id().to_bytes());

        xs.push(hash_to_curvebn(to_hash, params));
    }

    let mut e_summands: Vec<CurvePoint> = Vec::new();
    let mut v_summands: Vec<CurvePoint> = Vec::new();
    for i in 0..xs.len() {
        let cfrag = &capsule.attached_cfrags()[i];
        let x = &xs[i];
        if !cfrag.precursor().eq(&precursor) {
            return Err(PreErrors::InvalidCFrag);
        }
        let lambda_i = lambda_coeff(x, &xs);
        e_summands.push(cfrag.e_i_point() * &lambda_i);
        v_summands.push(cfrag.v_i_point() * &lambda_i);
    }

    let mut e_prime = e_summands[0].to_owned();
    let mut v_prime = v_summands[0].to_owned();
    for i in 1..e_summands.len() {
        e_prime = &e_prime + &e_summands[i];
        v_prime = &v_prime + &v_summands[i];
    }

    // Secret value 'd' allows to make Umbral non-interactive
    let mut to_hash = precursor.to_bytes();
    to_hash.append(&mut pk.to_bytes());
    to_hash.append(&mut dh_point.to_bytes());
    to_hash.append(&mut String::from("NON_INTERACTIVE").into_bytes());
    let d = hash_to_curvebn(to_hash, params);

    let (e, v, s) = (capsule.e(), capsule.v(), capsule.sign());
    let mut to_hash2 = e.to_bytes();
    to_hash2.append(&mut v.to_bytes());
    let h = hash_to_curvebn(to_hash2, params);

    let orig_pk = capsule.delegating_key();

    let first = orig_pk * &(s / &d);
    let second = &(&e_prime * &h) + &v_prime;
    if !first.eq(&second) {
        return Err(PreErrors::GenericError);
    }

    let shared_key = &(&e_prime + &v_prime) * &d;

    kdf(&shared_key.to_bytes())
}

fn _open_capsule(
    capsule: &Capsule,
    receiver_keypair: &KeyPair,
    check_proof: bool,
) -> Result<Vec<u8>, PreErrors> {
    if !capsule.verify() {
        return Err(PreErrors::InvalidCapsule);
    } else {
        if check_proof {
            let mut offending = false;
            for cfrag in capsule.attached_cfrags() {
                match cfrag.verify_correctness(capsule) {
                    Ok(correct) => offending = offending && correct,
                    Err(err) => return Err(err),
                }
            }
            if offending {
                return Err(PreErrors::InvalidCFrag);
            }
        }

        _decapsulate_reencrypted(&capsule, &receiver_keypair)
    }
}

pub fn decrypt(
    ciphertext: Vec<u8>,
    capsule: &Capsule,
    receiver_keypair: &KeyPair,
    check_proof: bool,
) -> Result<Vec<u8>, PreErrors> {
    if ciphertext.len() < DEM_MIN_SIZE {
        return Err(PreErrors::CiphertextError);
    }

    let encapsulated_key = match !capsule.attached_cfrags().is_empty() {
        //Since there are cfrags attached, we assume this is the receiver opening the Capsule.
        //(i.e., this is a re-encrypted capsule)
        true => _open_capsule(capsule, receiver_keypair, check_proof),
        //Since there aren't cfrags attached, we assume this is Alice opening the Capsule.
        //(i.e., this is an original capsule)
        false => _decapsulate(capsule, receiver_keypair.private_key()),
    };

    match encapsulated_key {
        Err(err) => return Err(err),
        Ok(key) => {
            return dem_decrypt(&key, &ciphertext);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curve::CurveBN;
    use crate::utils::poly_eval;
    use openssl::nid::Nid;
    use std::rc::Rc;

    #[test]
    fn encrypt_simple() {
        let params = Rc::new(Params::new(Nid::SECP256K1)); //Curve
        let (alice, _, _) = _generate_credentials(&params);

        // encrypt
        let plaintext = b"Hello, umbral!".to_vec();
        encrypt(&alice.public_key(), &plaintext);
    }

    #[test]
    fn poly_eval_test() {
        let params = Rc::new(Params::new(Nid::SECP256K1));
        let mut coefficients: Vec<CurveBN> = Vec::with_capacity(5);
        for i in 0..5 {
            coefficients.push(CurveBN::from_u32(i + 2, &params));
        }
        let x = CurveBN::from_u32(2, &params);

        let res = poly_eval(&coefficients, &x);
        let fin = res.eq(&CurveBN::from_u32(160, &params));
        assert_eq!(fin, true);
    }

    #[test]
    fn kfrags() {
        let params = Rc::new(Params::new(Nid::SECP256K1)); //Curve
        let (alice, signer, bob) = _generate_credentials(&params);

        // keyfrags
        generate_kfrags(&alice, &bob.public_key(), 2, 5, &signer);
    }

    #[test]
    fn false_verify_kfrag() {
        let params = Rc::new(Params::new(Nid::SECP256K1)); //Curve
        let (alice, signer, bob) = _generate_credentials(&params);
        let carl = KeyPair::new(&params);
        let carl_pk = carl.public_key();

        // encrypt
        let plaintext = b"Hello, umbral!".to_vec();
        let (_, mut capsule) = match encrypt(&alice.public_key(), &plaintext) {
            Ok(expr) => expr,
            Err(err) => panic!("{}", err),
        };

        //set correctness keys
        capsule.set_correctness_keys(&alice.public_key(), &carl_pk, &signer.public_key());

        // keyfrags
        let kfrags = generate_kfrags(&alice, &bob.public_key(), 2, 5, &signer).unwrap();

        let mut res = false;
        for kfrag in kfrags {
            res = res && kfrag.verify_for_capsule(&capsule)
        }

        assert_eq!(res, false);
    }

    #[test]
    fn reencrypt_simple() {
        let params = Rc::new(Params::new(Nid::SECP256K1)); //Curve
        let (alice, signer, bob) = _generate_credentials(&params);

        let plaintext = b"Hello, umbral!".to_vec();
        let (_, mut capsule) = match encrypt(&alice.public_key(), &plaintext) {
            Ok(expr) => expr,
            Err(err) => panic!("{}", err),
        };
        //set correctness keys
        capsule.set_correctness_keys(&alice.public_key(), &bob.public_key(), &signer.public_key());

        //kfrags
        let kfrags = generate_kfrags(&alice, &bob.public_key(), 2, 5, &signer).unwrap();

        //reencrypt
        let r = reencrypt(&kfrags[0], &capsule, true, true);
        assert_eq!(r.is_ok(), true);
    }

    #[test]
    fn attach_cfrag() {
        let params = Rc::new(Params::new(Nid::SECP256K1)); //Curve
        let (alice, signer, bob) = _generate_credentials(&params);

        let plaintext = b"Hello, umbral!".to_vec();
        let (_, mut capsule) = match encrypt(&alice.public_key(), &plaintext) {
            Ok(expr) => expr,
            Err(err) => panic!("{}", err),
        };
        //set correctness keys
        capsule.set_correctness_keys(&alice.public_key(), &bob.public_key(), &signer.public_key());

        //kfrags
        let kfrags = generate_kfrags(&alice, &bob.public_key(), 2, 5, &signer).unwrap();

        let mut res = true;
        for kfrag in kfrags {
            //reencrypt
            let cfrag = reencrypt(&kfrag, &capsule, true, true);
            //attach cfrag
            res = res && capsule.attach_cfrag(&cfrag.unwrap()).is_ok();
        }
        assert_eq!(res, true);
    }

    #[test]
    fn decrypt_frags() {
        let params = Rc::new(Params::new(Nid::SECP256K1)); //Curve
        let (alice, signer, bob) = _generate_credentials(&params);

        let plaintext = b"Hello, umbral!".to_vec();
        let (ciphertext, mut capsule) = match encrypt(&alice.public_key(), &plaintext) {
            Ok(expr) => expr,
            Err(err) => panic!("{}", err),
        };

        //set correctness keys
        capsule.set_correctness_keys(&alice.public_key(), &bob.public_key(), &signer.public_key());

        //kfrags
        let kfrags = generate_kfrags(&alice, &bob.public_key(), 2, 5, &signer).unwrap();

        for kfrag in kfrags {
            //reencrypt
            let cfrag = reencrypt(&kfrag, &capsule, true, true);
            //attach cfrag
            capsule.attach_cfrag(&cfrag.unwrap());
        }

        let res = decrypt(ciphertext, &capsule, &bob, true);
        let plaintext_bob = res.expect("Error in Decryption");
        println!("{:?}", String::from_utf8(plaintext_bob.to_owned()).unwrap());
        assert_eq!(plaintext, plaintext_bob);
    }

    #[test]
    fn decrypt_simple() {
        let params = Rc::new(Params::new(Nid::SECP256K1)); //Curve
        let (alice, _, _) = _generate_credentials(&params);

        let plaintext = b"Hello, umbral!".to_vec();
        let (ciphertext, capsule) = match encrypt(&alice.public_key(), &plaintext) {
            Ok(expr) => expr,
            Err(err) => panic!("{}", err),
        };

        let res = decrypt(ciphertext, &capsule, &alice, true);
        let plaintext_dec = res.expect("Error in Decryption");
        println!("{:?}", String::from_utf8(plaintext_dec.to_owned()).unwrap());
        assert_eq!(plaintext, plaintext_dec);
    }

    #[test]
    fn curve_bn() {
        let params = Rc::new(Params::new(Nid::SECP256K1)); //Curve
        let one = &CurveBN::from_u32(1, &params);
        let two = &CurveBN::from_u32(2, &params);
        let ten = &CurveBN::from_u32(10, &params);
        let three = one + two;
        assert_eq!(three.bn().to_vec(), vec![3; 1]);

        let nine = ten - one;
        assert_eq!(nine.bn().to_vec(), vec![9; 1]);

        let three_again = &nine / &three;
        assert_eq!(three_again.bn().to_vec(), vec![3; 1]);

        let eighteen = &nine * two;
        assert_eq!(eighteen.bn().to_vec(), vec![18; 1]);
    }

    fn _generate_credentials(params: &Rc<Params>) -> (KeyPair, Signer, KeyPair) {
        let alice = KeyPair::new(params);
        let signer = Signer::new(params);
        let bob = KeyPair::new(params);

        (alice, signer, bob)
    }
}
