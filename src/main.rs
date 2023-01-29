use std::sync::Arc;

use openssl::bn::{BigNum, BigNumRef};
use umbral_rs::internal::{keyredistrib::*, kfrag};
// use umbral_rs::pre::*;

fn main() {
    let params = new_standard_params();
    let alice = KeyPair::new(&params);
    let signer = Signer::new(&params);
    let bob = KeyPair::new(&params);

    let plaintext = b"Hello, umbral!".to_vec();
    let (ciphertext, mut capsule) = encrypt(&alice.public_key(), &plaintext).unwrap();

    capsule.set_correctness_keys(&alice.public_key(), &bob.public_key(), &signer.public_key());

    let threshold = 2;
    let nodes_number = 6;

    let kfrag_raw = generate_kfrags(
        &alice,
        &bob.public_key(),
        threshold,
        nodes_number,
        &signer,
        KFragMode::DelegatingAndReceiving,
    );
    let kfrags = kfrag_raw.0.unwrap();
    let dh_point = kfrag_raw.1;

    let mut cfrags: Vec<CFrag> = vec![];
    for kfrag in kfrags.iter() {
        let cfrag = reencrypt(&kfrag, &capsule, false, None, false).unwrap();

        cfrags.push(cfrag);
        // capsule.attach_cfrag(&cfrag).unwrap();
    }

    let mut cfrags_iter = cfrags.iter();

    let len_kfrags = nodes_number.clone();
    println!("kfrags len: {:?}", len_kfrags);

    let mut secret_vec: Vec<CurveBN> = vec![];
    let mut ids: Vec<&BigNumRef> = vec![];
    let precursor = kfrags[0].precursor();
    for kfrag in kfrags.iter() {
        secret_vec.push(kfrag.re_key_share().clone());
        ids.push(kfrag.id());
    }
    let res = key_refresh(
        &secret_vec,
        ids,
        dh_point,
        bob.public_key(),
        precursor,
        threshold as u32,
        &params,
    );
    println!("Result: {:?}", res);
    let u = CurvePoint::from_ec_point(params.u_point(), &params);
    // let mut new_share_for_secret: Vec<(CurveBN, CurveBN)> = vec![];

    let mut new_kfrags: Vec<KFrag> = vec![];
    let mut new_cfrags: Vec<CFrag> = vec![];
    let mut kfrag_iter = kfrags.iter();

    for share in res.iter() {
        // let share_num = share.0.clone() - 1;
        // let share_num_bignum = BigNum::from_u32(share.0.clone() as u32).unwrap();
        let curr_id = share.0.bn();

        let share_bn = share.1.clone();
        let curr_kfrag = kfrag_iter.next().unwrap();
        // let curr_kfrag = &kfrags[share_num as usize];
        // let id = curr_kfrag.id();
        let re_key_share = share_bn.clone();
        let commitment = &u * &re_key_share;
        let new_curr_kfrag = KFrag::new(
            curr_id,
            &re_key_share,
            &commitment,
            curr_kfrag.precursor(),
            curr_kfrag.signature_for_proxy(),
            curr_kfrag.signature_for_receiver(),
            curr_kfrag.keys_mode_in_signature(),
        );

        let new_curr_cfrag = refresh_cfrag(
            cfrags_iter.next().unwrap().clone(),
            curr_id,
            kfrag_get_rk(&curr_kfrag),
            &re_key_share,
        );

        // println!("new_curr_cfrag: {:?}", new_curr_cfrag);

        // let new_curr_cfrag2 = reencrypt(&new_curr_kfrag, &capsule, false, None, false).unwrap();

        // println!("new_curr_cfrag2:{:?}", new_curr_cfrag2);

        // assert!(new_curr_cfrag.eq(&new_curr_cfrag2));
        new_kfrags.push(new_curr_kfrag);
        new_cfrags.push(new_curr_cfrag);
    }

    for cfrag in new_cfrags.iter() {
        capsule.attach_cfrag(&cfrag).unwrap();
    }

    let plaintext_bob = decrypt(ciphertext, &capsule, &bob, false).unwrap();
    assert_eq!(plaintext, plaintext_bob);
    println!("{:?}", String::from_utf8(plaintext_bob.to_owned()).unwrap());
}
