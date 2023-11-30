pub use crate::internal::capsule::{CFrag, Capsule};
pub use crate::internal::keys::{KeyPair, Signer};
pub use crate::internal::kfrag::{KFrag, KFragMode};

use crate::internal::curve::Params;
use crate::internal::curve::{CurveBN, CurvePoint};
use crate::internal::errors::PreErrors;
use crate::internal::schemes::{dem_decrypt, dem_encrypt, hash_to_curve_blake, kdf, DEM_MIN_SIZE};
use crate::internal::utils::{lambda_coeff, new_constant_sorrow, poly_eval};
use std::rc::Rc;

use openssl::{
    bn::{BigNum, MsbOption},
    nid::Nid,
};

/// Creates the standard parameters needed to operate with this crate, i.e.
/// the SECP256K1 curve
pub fn new_standard_params() -> Rc<Params> {
    Rc::new(Params::new(Nid::SECP256K1)) //Curve
}

/// Performs an encryption using the DEM schema and encapsulates a key
/// for the sender using the public key provided.
///
/// Returns the ciphertext and the KEM Capsule.
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

/// Creates a re-encryption key from the delegating public key to the
/// receiving public key, and splits it in KFrags, using Shamir's Secret Sharing.
///
/// Requires a threshold number of KFrags out of N (`n` here).
///
/// Returns a list of N KFrags
/// Note: the name of this function in the paper is ReKeyGen
pub fn generate_kfrags(
    delegating_keypair: &KeyPair,
    receiving_pk: &CurvePoint,
    threshold: usize,
    n: usize,
    signer: &Signer,
    mode: KFragMode,
) -> (Result<Vec<KFrag>, PreErrors>, CurvePoint) {
    // a fake point to return in case of error
    let fake_point = CurvePoint::from_ec_point(
        delegating_keypair.public_key().params().u_point(),
        delegating_keypair.public_key().params(),
    );

    if threshold <= 0 || threshold > n {
        return (Err(PreErrors::InvalidKFragThreshold), fake_point);
    }
    if !(delegating_keypair
        .public_key()
        .params()
        .eq(receiving_pk.params()))
    {
        return (Err(PreErrors::KeysParametersNotEq), fake_point);
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
                return (Err(PreErrors::GenericError), fake_point);
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

    (Ok(kfrags), dh_point)
}

/// Performs the re-encryption operation of proxies and produces a capsule
/// fragment, i.e. a CFrag, from a KFrag given in input.
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

/// Opens the capsule and gets what's inside. If it is a symmetric key, then
/// it is used to decrypt the ciphertext and return the resulting cleartext.
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

pub fn _encapsulate(from_public_key: &CurvePoint) -> Result<(Vec<u8>, Capsule), PreErrors> {
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

pub fn _decapsulate(capsule: &Capsule, receiving: &CurveBN) -> Result<Vec<u8>, PreErrors> {
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
    use crate::internal::keys::Signature;
    //use std::{thread, time};

    #[test]
    fn encrypt_simple() {
        let params = new_standard_params();
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
        let params = new_standard_params();
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
        let params = new_standard_params();
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
            (Ok(_), _) => assert_eq!(true, true),
            _ => panic!("Error in generate_kfrags"),
        };
    }

    #[test]
    fn false_verify_kfrag() {
        let params = new_standard_params();
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
            (Ok(ks), _) => ks,
            _ => panic!("Error in generate_kfrags"),
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
        let params = new_standard_params();
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
            (Ok(ks), _) => ks,
            _ => panic!("Error in generate_kfrags"),
        };

        //reencrypt
        let r = reencrypt(&kfrags[0], &capsule, true, None, true);
        assert_eq!(r.is_ok(), true);
    }

    #[test]
    fn attach_cfrag() {
        let params = new_standard_params();
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
            (Ok(ks), _) => ks,
            _ => panic!("Error in generate_kfrags"),
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
        let params = new_standard_params();
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
            (Ok(ks), _) => ks,
            _ => panic!("Error in generate_kfrags"),
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
        let params = new_standard_params();
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
        let params = new_standard_params();
        hash_to_curve_blake(&b"gadhj".to_vec(), &params);
    }

    #[test]
    fn curve_bn() {
        let params = new_standard_params();
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
        let params = new_standard_params();
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
            (Ok(ks), _) => ks,
            _ => panic!("Error in generate_kfrags"),
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
        capsule.set_correctness_keys(&alice.public_key(), &bob.public_key(), &signer.public_key());
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
    /*
    #[test]
    fn new_test_mule_1() {
      let params = new_standard_params();
      let (alice, signer, bob) = _generate_credentials(&params);

      //////////// Generate key x
      // BN context needed for the heap
      let params = alice.public_key().params();
      // R point generation
      let r = KeyPair::new(params);
      let u = KeyPair::new(params);
      let shared_key = alice.public_key() * &(r.private_key() + u.private_key());
      let key_x = match kdf(&shared_key.to_bytes()) {
        Ok(key) => key,
        Err(err) => panic!("{}", err),
      };
      ////////////

      let sizes: [usize; 7] = [10485, 52428, 104857, 524288, 1048576, 5242880, 10485760];

      for outer in 0..7 {
        let mut slice_payload = vec![0u8; sizes[outer]].into_boxed_slice();
        getrandom::getrandom(&mut slice_payload).expect("Error in payload generation");
        let plaintext = slice_payload.to_vec(); //b"Hello, umbral!".to_vec();
        let ciphertext = match dem_encrypt(&key_x, &plaintext, None) {
          Ok(ciphertext) => ciphertext,
          Err(err) => panic!("{}", err),
        };

        let tries = 10;
        let mut duration_enc = 0;
        let mut duration_dec = 0;
        for _ in 0..10 {
          //////////// Encrypt
          let now_enc = time::Instant::now();
          // Tender
          let mut slice_tender = vec![0u8; 150].into_boxed_slice();
          getrandom::getrandom(&mut slice_tender).expect("Error in tender generation");
          let tender = slice_tender.to_vec();
          let tender_signature = signer.sign_sha2(&tender);
          // Balance
          let mut slice_balance = vec![0u8; 110].into_boxed_slice();
          getrandom::getrandom(&mut slice_balance).expect("Error in balance generation");
          let balance = slice_balance.to_vec();
          let balance_signature = signer.sign_sha2(&balance);
          // Address
          let mut slice_address = vec![0u8; 42].into_boxed_slice();
          getrandom::getrandom(&mut slice_address).expect("Error in address generation");
          let address = slice_address.to_vec();
          let address_signature = signer.sign_sha2(&address);
          // Shared key
          let shared_key_alice = bob.public_key() * alice.private_key();
          let key_alice = match kdf(&shared_key_alice.to_bytes()) {
            Ok(key) => key,
            Err(err) => panic!("{}", err),
          };
          let other_data = {
            let mut r = tender.clone();
            r.extend_from_slice(&tender_signature.to_bytes());
            r.extend_from_slice(&balance);
            r.extend_from_slice(&balance_signature.to_bytes());
            r.extend_from_slice(&address_signature.to_bytes());
            r
          };
          let other_data_ciphertext = match dem_encrypt(&key_alice, &other_data, None) {
            Ok(ciphertext) => ciphertext,
            Err(err) => panic!("{}", err),
          };
          duration_enc += now_enc.elapsed().as_millis();

          //////////// Decrypt
          let now_dec = time::Instant::now();
          let shared_key_bob = alice.public_key() * bob.private_key();
          let key_bob = match kdf(&shared_key_bob.to_bytes()) {
            Ok(key) => key,
            Err(err) => panic!("{}", err),
          };
          let other_data_dec = match dem_decrypt(&key_bob, &other_data_ciphertext, None) {
            Ok(p) => p,
            Err(err) => panic!("{}", err),
          };
          let tender_verification = tender_signature.verify_sha2(&tender, &signer.public_key());
          assert_eq!(tender_verification, true);
          let balance_verification = balance_signature.verify_sha2(&balance, &signer.public_key());
          assert_eq!(balance_verification, true);
          let address_verification = address_signature.verify_sha2(&address, &signer.public_key());
          assert_eq!(address_verification, true);
          duration_dec += now_dec.elapsed().as_millis();
          assert_eq!(other_data, other_data_dec);
        }
        println!(
          "Enc {:?}, Dec {:?}",
          duration_enc / tries,
          duration_dec / tries
        );
      }
    }

    #[test]
    fn new_test_mule_2() {
      let params = new_standard_params();
      let (alice, signerb, bob) = _generate_credentials(&params);
      let (_, signera, _) = _generate_credentials(&params);

      //////////// Public key encryption
      // BN context needed for the heap
      let params = alice.public_key().params();
      // R point generation
      let r = KeyPair::new(params);
      let u = KeyPair::new(params);
      let shared_key = alice.public_key() * &(r.private_key() + u.private_key());
      let key_x = match kdf(&shared_key.to_bytes()) {
        Ok(key) => key,
        Err(err) => panic!("{}", err),
      };
      ////////////

      let sizes: [usize; 7] = [10485, 52428, 104857, 524288, 1048576, 5242880, 10485760];

      for outer in 0..7 {
        let mut slice_payload = vec![0u8; sizes[outer]].into_boxed_slice();
        getrandom::getrandom(&mut slice_payload).expect("Error in payload generation");
        let plaintext = slice_payload.to_vec();
        //////////// R Public key encryption 2
        let ciphertext = match dem_encrypt(&key_x, &plaintext, None) {
          Ok(ciphertext) => ciphertext,
          Err(err) => panic!("{}", err),
        };
        //////////// Bob encryption
        // Tender
        let mut slice_tender = vec![0u8; 96].into_boxed_slice();
        getrandom::getrandom(&mut slice_tender).expect("Error in tender generation");
        let tender = slice_tender.to_vec();
        let tender_signature = signerb.sign_sha2(&tender);
        // Shared key
        let shared_key_bob = alice.public_key() * bob.private_key();
        let key_bob = match kdf(&shared_key_bob.to_bytes()) {
          Ok(key) => key,
          Err(err) => panic!("{}", err),
        };
        let other_data_tender = {
          let mut r = tender.clone();
          r.extend_from_slice(&tender_signature.to_bytes());
          r
        };
        let other_data_tender_ciphertext = match dem_encrypt(&key_bob, &other_data_tender, None) {
          Ok(ciphertext) => ciphertext,
          Err(err) => panic!("{}", err),
        };

        let tries = 10;
        let mut duration_dec_tender = 0;
        let mut duration_enc_balance = 0;
        let mut duration_dec_balance = 0;
        let mut duration_dec_plaintext = 0;
        for _ in 0..10 {
          //////////// Tender Decrypt
          let now_dec = time::Instant::now();
          let shared_key_alice = bob.public_key() * alice.private_key();
          let key_alice = match kdf(&shared_key_alice.to_bytes()) {
            Ok(key) => key,
            Err(err) => panic!("{}", err),
          };
          let other_data_tender_dec =
            match dem_decrypt(&key_alice, &other_data_tender_ciphertext, None) {
              Ok(p) => p,
              Err(err) => panic!("{}", err),
            };
          let tender_verification = tender_signature.verify_sha2(&tender, &signerb.public_key());
          assert_eq!(tender_verification, true);
          duration_dec_tender += now_dec.elapsed().as_millis();
          assert_eq!(other_data_tender, other_data_tender_dec);

          //////////// Encrypt
          let now_enc = time::Instant::now();
          // Balance
          let mut slice_balance = vec![0u8; 110].into_boxed_slice();
          getrandom::getrandom(&mut slice_balance).expect("Error in balance generation");
          let balance = slice_balance.to_vec();
          let balance_signature = signera.sign_sha2(&balance);
          let other_data_balance = {
            let mut r = balance.clone();
            r.extend_from_slice(&balance_signature.to_bytes());
            r
          };
          let other_data_balance_ciphertext = match dem_encrypt(&key_alice, &other_data_balance, None)
          {
            Ok(ciphertext) => ciphertext,
            Err(err) => panic!("{}", err),
          };
          duration_enc_balance += now_enc.elapsed().as_millis();

          //////////// Bob Decrypt
          let now_dec_2 = time::Instant::now();
          let other_data_balance_dec =
            match dem_decrypt(&key_bob, &other_data_balance_ciphertext, None) {
              Ok(p) => p,
              Err(err) => panic!("{}", err),
            };
          let balance_verification = balance_signature.verify_sha2(&balance, &signera.public_key());
          assert_eq!(balance_verification, true);
          duration_dec_balance += now_dec_2.elapsed().as_millis();
          assert_eq!(other_data_balance, other_data_balance_dec);

          //////////// Payload Decrypt
          let now_dec_3 = time::Instant::now();
          let shared_key_ecies = &(r.public_key() + u.public_key()) * alice.private_key();
          let key_ecies = match kdf(&shared_key_ecies.to_bytes()) {
            Ok(key) => key,
            Err(err) => panic!("{}", err),
          };
          let plaintext_dec = match dem_decrypt(&key_ecies, &ciphertext, None) {
            Ok(p) => p,
            Err(err) => panic!("{}", err),
          };
          duration_dec_plaintext += now_dec_3.elapsed().as_millis();
          assert_eq!(plaintext, plaintext_dec);
        }
        println!(
          "Dec Tender {:?}, Enc Balance {:?}, Dec Balance {:?}, Dec Payload {:?}",
          duration_dec_tender / tries,
          duration_enc_balance / tries,
          duration_dec_balance / tries,
          duration_dec_plaintext / tries
        );
      }
    }
    */
}
