extern crate quick_error;
mod capsule;
mod curve;
mod errors;
mod keys;
mod kfrag;
mod schemes;
mod utils;

pub use crate::capsule::{CFrag, Capsule};
pub use crate::curve::{CurveBN, CurvePoint, Params};
pub use crate::errors::PreErrors;
pub use crate::keys::{KeyPair, Signer};
pub use crate::kfrag::{KFrag, KFragMode};
pub use crate::schemes::{dem_decrypt, dem_encrypt, hash_to_curve_blake, kdf, DEM_MIN_SIZE};
pub use crate::utils::{lambda_coeff, new_constant_sorrow, poly_eval};

use openssl::bn::{BigNum, MsbOption};

pub fn encrypt(
    from_public_key: &CurvePoint,
    plaintext: &Vec<u8>,
) -> Result<(Vec<u8>, Capsule), PreErrors> {
    let (key, capsule) = match _encapsulate(&from_public_key) {
        Ok(kc) => kc,
        Err(err) => return Err(err),
    };

    match dem_encrypt(&key, plaintext, Some(&capsule.to_bytes())) {
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
    mode: KFragMode,
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
    to_hash.append(&mut new_constant_sorrow("NON_INTERACTIVE"));

    // Secret value 'd' allows to make Umbral non-interactive
    let d = hash_to_curve_blake(&to_hash, params);

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
    let order_bits_size = params.order().num_bits();
    for _ in 0..n {
        let mut kfrag_id = BigNum::new().unwrap();
        match kfrag_id.rand(order_bits_size, MsbOption::MAYBE_ZERO, false) {
            Ok(_) => (),
            Err(_) => {
                return Err(PreErrors::GenericError);
            }
        }

        let mut to_hash_it = to_hash2.clone();
        to_hash_it.append(&mut new_constant_sorrow("X_COORDINATE"));
        to_hash_it.append(&mut kfrag_id.to_vec());

        /*
            The index of the re-encryption key share (which in Shamir's Secret
            Sharing corresponds to x in the tuple (x, f(x)), with f being the
            generating polynomial), is used to prevent reconstruction of the
            re-encryption key without Bob's intervention
        */
        let share_index = hash_to_curve_blake(&to_hash_it, params);

        /*
            The re-encryption key share is the result of evaluating the generating
            polynomial for the index value
        */
        let rk = poly_eval(&coefficients, &share_index);

        let u = CurvePoint::from_ec_point(params.u_point(), params);
        let commitment_point = &u * &rk;

        // Signing for receiver
        let mut to_hash_it2 = kfrag_id.to_vec();
        to_hash_it2.append(&mut delegating_keypair.public_key().to_bytes());
        to_hash_it2.append(&mut receiving_pk.to_bytes());
        to_hash_it2.append(&mut commitment_point.to_bytes());
        to_hash_it2.append(&mut precursor.public_key().to_bytes());
        let signature_for_receiver = signer.sign_sha2(&to_hash_it2);

        // Signing for proxy
        let mut to_hash_it3 = kfrag_id.to_vec();
        to_hash_it3.append(&mut commitment_point.to_bytes());
        to_hash_it3.append(&mut precursor.public_key().to_bytes());
        match mode {
            KFragMode::DelegatingAndReceiving => {
                to_hash_it3.append(
                    &mut (KFragMode::DelegatingAndReceiving as u8)
                        .to_ne_bytes()
                        .to_vec(),
                );
                to_hash_it3.append(&mut delegating_keypair.public_key().to_bytes());
                to_hash_it3.append(&mut receiving_pk.to_bytes());
            }
            KFragMode::DelegatingOnly => {
                to_hash_it3.append(&mut (KFragMode::DelegatingOnly as u8).to_ne_bytes().to_vec());
                to_hash_it3.append(&mut delegating_keypair.public_key().to_bytes());
            }
            KFragMode::ReceivingOnly => {
                to_hash_it3.append(&mut (KFragMode::ReceivingOnly as u8).to_ne_bytes().to_vec());
                to_hash_it3.append(&mut receiving_pk.to_bytes());
            }
            KFragMode::NoKey => {
                to_hash_it3.append(&mut (KFragMode::NoKey as u8).to_ne_bytes().to_vec());
            }
        }
        let signature_for_proxy = signer.sign_sha2(&to_hash_it3);

        kfrags.push(KFrag::new(
            &kfrag_id,
            &rk,
            &commitment_point,
            &precursor.public_key(),
            &signature_for_proxy,
            &signature_for_receiver,
            mode,
        ));
    }

    Ok(kfrags)
}

pub fn reencrypt(
    kfrag: &KFrag,
    capsule: &Capsule,
    provide_proof: bool,
    metadata: Option<Vec<u8>>,
    verify_kfrag: bool,
) -> Result<CFrag, PreErrors> {
    if !capsule.verify() {
        return Err(PreErrors::InvalidCapsule);
    }

    if verify_kfrag {
        match kfrag.verify_for_capsule(capsule) {
            Ok(res) => {
                if !res {
                    return Err(PreErrors::InvalidKFrag);
                }
            }
            Err(err) => return Err(err),
        }
    }

    let rk = kfrag.re_key_share();
    let e_i = capsule.e() * rk;
    let v_i = capsule.v() * rk;

    let mut cfrag = CFrag::new(&e_i, &v_i, kfrag.id(), kfrag.precursor());

    if provide_proof {
        match cfrag.prove_correctness(capsule, kfrag, metadata) {
            Ok(_) => (),
            Err(err) => return Err(err),
        }
    }

    return Ok(cfrag);
}

pub fn decrypt(
    ciphertext: Vec<u8>,
    capsule: &Capsule,
    decrypting_keypair: &KeyPair,
    check_proof: bool,
) -> Result<Vec<u8>, PreErrors> {
    if ciphertext.len() < DEM_MIN_SIZE {
        return Err(PreErrors::CiphertextError);
    }

    let encapsulated_key = match !capsule.attached_cfrags().is_empty() {
        //Since there are cfrags attached, we assume this is the receiver opening the Capsule.
        //(i.e., this is a re-encrypted capsule)
        true => _open_capsule(capsule, decrypting_keypair, check_proof),
        //Since there aren't cfrags attached, we assume this is Alice opening the Capsule.
        //(i.e., this is an original capsule)
        false => _decapsulate(capsule, decrypting_keypair.private_key()),
    };

    match encapsulated_key {
        Ok(key) => dem_decrypt(&key, &ciphertext, Some(&capsule.to_bytes())),
        Err(err) => Err(err),
    }
}

fn _encapsulate(from_public_key: &CurvePoint) -> Result<(Vec<u8>, Capsule), PreErrors> {
    // BN context needed for the heap
    let params = from_public_key.params();

    // R point generation
    let r = KeyPair::new(params);
    let u = KeyPair::new(params);

    // Get sign
    let mut to_hash = r.public_key().to_bytes();
    to_hash.append(&mut u.public_key().to_bytes());
    let h = hash_to_curve_blake(&to_hash, params);

    let s = u.private_key() + &(r.private_key() * &h);

    let shared_key = from_public_key * &(r.private_key() + u.private_key());

    match kdf(&shared_key.to_bytes()) {
        Ok(key) => Ok((key, Capsule::new(r.public_key(), u.public_key(), &s))),
        Err(err) => Err(err),
    }
}

fn _decapsulate(capsule: &Capsule, receiving: &CurveBN) -> Result<Vec<u8>, PreErrors> {
    if !capsule.verify() {
        return Err(PreErrors::InvalidCapsule);
    }

    let shared_key = &(capsule.e() + capsule.v()) * receiving;
    kdf(&shared_key.to_bytes())
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
        to_hash.append(&mut new_constant_sorrow("X_COORDINATE"));
        to_hash.append(&mut cfrag.kfrag_id().to_vec());

        xs.push(hash_to_curve_blake(&to_hash, params));
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
    to_hash.append(&mut new_constant_sorrow("NON_INTERACTIVE"));
    let d = hash_to_curve_blake(&to_hash, params);

    let (e, v, s) = (capsule.e(), capsule.v(), capsule.sign());
    let mut to_hash2 = e.to_bytes();
    to_hash2.append(&mut v.to_bytes());
    let h = hash_to_curve_blake(&to_hash2, params);

    let orig_pk = match capsule.delegating_key() {
        Some(d) => d,
        None => return Err(PreErrors::CapsuleNoCorrectnessProvided),
    };

    let first = orig_pk * &(s / &d);
    let second = &(&e_prime * &h) + &v_prime;
    if !first.eq(&second) {
        return Err(PreErrors::DecryptionError);
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
    }

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curve::CurveBN;
    use crate::keys::Signature;
    use crate::utils::poly_eval;
    use openssl::nid::Nid;
    use std::rc::Rc;

    #[test]
    fn encrypt_simple() {
        let params = Rc::new(Params::new(Nid::SECP256K1)); //Curve
        let (alice, _, _) = _generate_credentials(&params);

        // encrypt
        let plaintext = b"Hello, umbral!".to_vec();
        match encrypt(&alice.public_key(), &plaintext) {
            Ok(_) => assert_eq!(true, true),
            Err(err) => panic!("Error: {}", err),
        };
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
        match generate_kfrags(
            &alice,
            &bob.public_key(),
            2,
            5,
            &signer,
            KFragMode::DelegatingAndReceiving,
        ) {
            Ok(_) => assert_eq!(true, true),
            Err(err) => panic!("Error: {}", err),
        };
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
        let kfrags = match generate_kfrags(
            &alice,
            &bob.public_key(),
            2,
            5,
            &signer,
            KFragMode::DelegatingAndReceiving,
        ) {
            Ok(ks) => ks,
            Err(err) => panic!("Error: {}", err),
        };

        let mut res = false;
        for kfrag in kfrags {
            res = res
                && kfrag
                    .verify_for_capsule(&capsule)
                    .expect("Errors in KFrag verifying")
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
        let kfrags = match generate_kfrags(
            &alice,
            &bob.public_key(),
            2,
            5,
            &signer,
            KFragMode::DelegatingAndReceiving,
        ) {
            Ok(ks) => ks,
            Err(err) => panic!("Error: {}", err),
        };

        //reencrypt
        let r = reencrypt(&kfrags[0], &capsule, true, None, true);
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
        let kfrags = match generate_kfrags(
            &alice,
            &bob.public_key(),
            2,
            5,
            &signer,
            KFragMode::DelegatingAndReceiving,
        ) {
            Ok(ks) => ks,
            Err(err) => panic!("Error: {}", err),
        };

        let mut res = true;
        for kfrag in kfrags {
            //reencrypt
            let cfrag = match reencrypt(&kfrag, &capsule, true, None, true) {
                Ok(expr) => expr,
                Err(err) => panic!("{}", err),
            };
            //attach cfrag
            res = res && capsule.attach_cfrag(&cfrag).is_ok();
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
        let kfrags = match generate_kfrags(
            &alice,
            &bob.public_key(),
            2,
            5,
            &signer,
            KFragMode::DelegatingAndReceiving,
        ) {
            Ok(ks) => ks,
            Err(err) => panic!("Error: {}", err),
        };

        for kfrag in kfrags {
            //reencrypt
            let cfrag = match reencrypt(&kfrag, &capsule, true, None, true) {
                Ok(expr) => expr,
                Err(err) => panic!("{}", err),
            };
            //attach cfrag
            match capsule.attach_cfrag(&cfrag) {
                Ok(_) => (),
                Err(err) => panic!("{}", err),
            };
        }

        let res = decrypt(ciphertext, &capsule, &bob, true);
        let plaintext_bob = match res {
            Ok(p) => p,
            Err(err) => panic!("Error {}", err),
        };
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
    fn hash_to_bn() {
        let params = Rc::new(Params::new(Nid::SECP256K1)); //Curve
        let kl = hash_to_curve_blake(&b"gadhj".to_vec(), &params);

        println!("{:?}", kl.bn());
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

    #[test]
    fn bytes_conv() {
        let params = Rc::new(Params::new(Nid::SECP256K1));
        let (alice, signer, bob) = _generate_credentials(&params);
        // CurveBN and CurvePoint
        let r = CurveBN::rand_curve_bn(&params);
        let p = CurvePoint::mul_gen(&r, &params);
        let r_bytes = r.to_bytes();
        let p_bytes = p.to_bytes();
        let p_new = CurvePoint::from_bytes(&p_bytes, &params).expect("Point");
        assert_eq!(p.eq(&p_new), true);
        let r_new = CurveBN::from_bytes(&r_bytes, &params).expect("BN");
        assert_eq!(r.eq(&r_new), true);
        let p_new2 = CurvePoint::mul_gen(&r_new, &params);
        assert_eq!(p.eq(&p_new2), true);
        // Signature
        let s = signer.sign_sha2(&p_bytes);
        let s_bytes = s.to_bytes();
        let s_new = Signature::from_bytes(&s_bytes, &params).expect("Signature");
        assert_eq!(s.eq(&s_new), true);
        //KFrags
        let kfs = match generate_kfrags(
            &alice,
            &bob.public_key(),
            1,
            1,
            &signer,
            KFragMode::DelegatingAndReceiving,
        ) {
            Ok(ks) => ks,
            Err(err) => panic!("Error: {}", err),
        };
        let kf_bytes = kfs[0].to_bytes();
        let kf_new = KFrag::from_bytes(&kf_bytes, &params).expect("KFrag");
        assert_eq!(kfs[0].eq(&kf_new), true);
        // Capsule
        let (_, mut capsule) = match encrypt(&alice.public_key(), &b"Hello, umbral!".to_vec()) {
            Ok(expr) => expr,
            Err(err) => panic!("{}", err),
        };
        let capsule_bytes = capsule.to_bytes();
        let capsule_new = Capsule::from_bytes(&capsule_bytes, &params).expect("Capsule");
        assert_eq!(capsule.eq(&capsule_new), true);
        //CFrags
        capsule.set_correctness_keys(&alice.public_key(), &bob.public_key(), &signer.public_key()); //TODO error handling
        let cfrag = match reencrypt(&kf_new, &capsule, true, None, true) {
            Ok(expr) => expr,
            Err(err) => panic!("{}", err),
        };
        let cfrag_bytes = cfrag.to_bytes();
        let cfrag_new = CFrag::from_bytes(&cfrag_bytes, &params).expect("CFrag");
        assert_eq!(cfrag.eq(&cfrag_new), true);
    }

    fn _generate_credentials(params: &Rc<Params>) -> (KeyPair, Signer, KeyPair) {
        let alice = KeyPair::new(params);
        let signer = Signer::new(params);
        let bob = KeyPair::new(params);

        (alice, signer, bob)
    }
}
