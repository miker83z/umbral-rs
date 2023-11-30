pub use crate::internal::capsule::*;
pub use crate::internal::curve::{CurveBN, CurvePoint, Params};
pub use crate::internal::keys::*;
pub use crate::internal::kfrag::*;
pub use crate::internal::schemes::hash_to_curve_blake;
pub use crate::internal::utils::*;
pub use crate::pre::*;
use openssl::bn::BigNumRef;
use std::collections::HashMap;

pub fn vec_to_hex(v: &[u8]) -> String {
    v.iter().map(|b| format!("{:02x}", b)).collect()
}

// const PARAMS: Rc<Params> = new_standard_params();

pub fn kfrag_get_rk(kfrag: &KFrag) -> &CurveBN {
    let rk = kfrag.re_key_share();
    rk
}

pub fn refresh_cfrag(cfrag: CFrag, id: &BigNumRef, old_rk: &CurveBN, new_rk: &CurveBN) -> CFrag {
    let e_i_point = cfrag.e_i_point();
    let v_i_point = cfrag.v_i_point();
    // println!("the proof: {:?}", cfrag.proof());
    // let proof = cfrag.proof().clone().unwrap_or_else(|| panic!("No proof"));
    let factor = new_rk * &old_rk.invert();
    let new_e_i_point = e_i_point * &factor;
    let new_v_i_point = v_i_point * &factor;

    let new_cfrag = CFrag::new(&new_e_i_point, &new_v_i_point, id, &cfrag.precursor());

    // let new_cfrag = CFrag::new_with_fake_proof(
    //     &new_e_i_point,
    //     &new_v_i_point,
    //     &cfrag.kfrag_id(),
    //     &cfrag.precursor(),
    //     &proof,
    // );

    new_cfrag
}

fn get_share_index(
    kfrag_id: &BigNumRef,
    precursor: &CurvePoint,
    dh_point: &CurvePoint,
    receiving_pk: &CurvePoint,
    params: &Rc<Params>,
) -> CurveBN {
    let mut to_hash = precursor.to_bytes();
    to_hash.append(&mut receiving_pk.to_bytes());
    to_hash.append(&mut dh_point.to_bytes());
    let to_hash2 = to_hash.clone();
    to_hash.append(&mut new_constant_sorrow("NON_INTERACTIVE"));

    let mut to_hash_it = to_hash2.clone();
    to_hash_it.append(&mut new_constant_sorrow("X_COORDINATE"));
    to_hash_it.append(&mut kfrag_id.to_vec());
    let share_index = hash_to_curve_blake(&to_hash_it, params);
    share_index
}

fn _get_dh(precursor: &KeyPair, receiving_pk: &CurvePoint) -> CurvePoint {
    let dh_point = receiving_pk * precursor.private_key();
    dh_point
}

// make a function that takes a two keypairs and swaps them
pub fn swap_keypairs(a: &KeyPair, b: &KeyPair) -> (KeyPair, KeyPair) {
    let a_copy = KeyPair::from_bytes(
        &a.public_key().to_bytes(),
        &a.private_key().to_bytes(),
        &new_standard_params(),
    )
    .unwrap();
    let b_copy = KeyPair::from_bytes(
        &b.public_key().to_bytes(),
        &b.private_key().to_bytes(),
        &new_standard_params(),
    )
    .unwrap();
    (b_copy, a_copy)
}

fn random_coefficients(secret: CurveBN, t: u32, params: &Rc<Params>) -> Vec<CurveBN> {
    // let mut rng = thread_rng();
    // let zero = CurveBN::from_u32(0, &params);
    let mut coefficients: Vec<CurveBN> = Vec::with_capacity(t as usize);
    for _ in 0..t {
        coefficients.push(CurveBN::rand_curve_bn(&params));
    }
    coefficients[0] = secret;
    coefficients
}

fn create_shares_with_ids(
    coefficients: &Vec<CurveBN>,
    ids: &Vec<CurveBN>,
    _params: &Rc<Params>,
) -> Vec<(CurveBN, CurveBN)> {
    // convert ids to curve points
    let mut shares = Vec::with_capacity(ids.len());
    for i in ids.iter() {
        shares.push((i.clone(), poly_eval(coefficients, i)));
    }
    shares
}

// given t shares, compute lagrange coefficients
fn compute_lagrange_coefficients(
    shares: &Vec<(CurveBN, CurveBN)>,
    params: &Rc<Params>,
) -> Vec<CurveBN> {
    let shares_len = shares.len();
    let mut coefficients = Vec::with_capacity(shares_len);
    for i in 0..shares_len {
        let mut numerator = CurveBN::from_u32(1, &params);
        let mut denominator = CurveBN::from_u32(1, &params);
        for j in 0..shares_len {
            if i != j {
                numerator = &numerator * &shares[j].0;
                // numerator = numerator.rem_euclid(q);
                denominator = &denominator * &(&shares[j].0 - &shares[i].0);
                // denominator = denominator.rem_euclid(q);
            }
        }
        coefficients.push(&(&numerator * &shares[i].1) * &denominator.invert());
    }
    coefficients
}

// given t shares, compute secret
fn compute_secret(shares: &Vec<(CurveBN, CurveBN)>, params: &Rc<Params>) -> CurveBN {
    let lag_coefficients = compute_lagrange_coefficients(shares, &params);
    let mut lag_coefficients_iter = lag_coefficients.iter();
    let mut secret = CurveBN::from_u32(0, &params);

    for _ in 0..shares.len() {
        secret = &secret + &lag_coefficients_iter.next().unwrap();
    }

    secret
}

pub fn key_refresh(
    priv_key_vec: &Vec<CurveBN>,
    ids: Vec<&BigNumRef>,
    dh_point: CurvePoint,
    receiving_pk: &CurvePoint,
    precursor: &CurvePoint,
    threshold: u32,
    params: &Rc<Params>,
) -> HashMap<CurveBN, CurveBN> {
    let _ = priv_key_vec.len();
    // println!(
    //     "key_refresh: N: {}, threshold: {}, priv_key_vec: {:?}",
    //     N, threshold, priv_key_vec
    // );

    // split every "share as a key" in many subshares
    let mut shares_dict_for_others = HashMap::new();
    let mut priv_key_vec_iter = priv_key_vec.iter();
    let share_indexes = ids
        .iter()
        .map(|x| get_share_index(*x, &precursor, &dh_point, receiving_pk, params))
        .collect::<Vec<CurveBN>>();
    for i in share_indexes.iter() {
        let coefficients = random_coefficients(
            priv_key_vec_iter.next().unwrap().clone(),
            threshold,
            &params,
        );
        let shares = create_shares_with_ids(&coefficients, &share_indexes, &params);
        shares_dict_for_others.insert(i.clone(), shares);
    }

    // each party uses its shares to create a new share for himself
    let mut shares_dict_from_others: HashMap<CurveBN, CurveBN> = HashMap::new();
    let share_indexes_clone = share_indexes.clone();
    let mut id_iter = ids.iter();
    for i in share_indexes.iter() {
        // let mut i_share: (CurveBN, CurveBN);
        // let i_bn = CurveBN::from_u32(i as u32, &params);
        let i_bn = i.clone();
        // let mut i_share: (CurveBN, CurveBN) = (i_bn.clone(), CurveBN::from_u32(0, &params));
        let mut i_share_vec = Vec::new();
        //get others share
        for j in share_indexes_clone.iter() {
            let j_bn = j.clone();
            // let j_bn = CurveBN::from_u32(j as u32, &params);
            // if i != j {
            // i gets its shares from all js
            let vect_of_shares = shares_dict_for_others.get(&j_bn).unwrap();

            for share in vect_of_shares.iter() {
                if share.0.eq(&i_bn) {
                    let i_share = (j_bn.clone(), share.1.clone());
                    i_share_vec.push(i_share);
                }
                // break;
                // }
            }
            // i_share_vec.push(i_share);
        }

        let new_secret = compute_secret(&i_share_vec, &params);
        shares_dict_from_others.insert(
            CurveBN::from_big_num(id_iter.next().unwrap(), params),
            new_secret,
        );
    }

    shares_dict_from_others
}

//     let mut curr_share: &(CurveBN, CurveBN);
//     let mut new_priv_keys = HashMap::new();
//     for i in 0..N - 1 {
//         let mut share_sum = CurveBN::from_u32(0, &params);
//         let mut shares_dict_for_others_iter = shares_dict_for_others[&i].iter();
//         for j in 0..N - 1 {
//             let mut interim_share = shares_dict_for_others_iter.next().unwrap();
//             if i != j {
//                 curr_share = interim_share;
//                 share_sum = &share_sum + &curr_share.1;
//             }
//         }
//         new_priv_keys.insert(i, share_sum);
//     }

//     for i in 0..N - 1 {
//         let mut
//         println!("new_priv_keys[{}]: {:?}", i, new_priv_keys[&i]);
//     }

//     new_priv_keys
// }
#[cfg(test)]
mod tests {
    use super::*;
    use modinverse::modinverse;
    // pub use crate::internal::keyredistrib::*;
    // use crate::pre::*;

    // convert private key to BN
    fn _priv_key_to_bn(priv_key: &Vec<u8>) {
        let params = new_standard_params();
        let _curve_bn = CurveBN::from_bytes(&priv_key, &params).unwrap();
        // &curve_bn.bn()
    }

    // given number x and modulus q invert x mod q
    fn mod_inv(x: i32, q: i32) -> Option<i32> {
        let x = x.rem_euclid(q);

        let res = modinverse(x, q);
        match res {
            Some(_) => res,
            None => panic!(
                "Error in mod_inv, modinverse returned None, q: {}, x: {}",
                q, x,
            ),
        }
    }

    fn compute_polynomial(coefficients: &Vec<CurveBN>, x: u32, params: &Rc<Params>) -> CurveBN {
        // let mut y: CurveBN = CurveBN::from_u32(0, &params);
        // let mut x_pow: u32;
        // let mut x_curve_bn: CurveBN;
        // let mut y_curve_bn: CurveBN;
        // let mut coefficients_iter = coefficients.iter();
        // for i in 0..coefficients.len() {
        //     x_pow = x.pow(i as u32);
        //     x_curve_bn = CurveBN::from_u32(x_pow, &params);
        //     // y_curve_bn = coefficients_iter.next().unwrap();
        //     y = &y + &(coefficients_iter.next().unwrap() * &x_curve_bn);
        // }
        // y

        let x_bn = CurveBN::from_u32(x, &params);
        let res = poly_eval(coefficients, &x_bn);
        res
    }

    fn create_shares(
        coefficients: &Vec<CurveBN>,
        num_shares: u32,
        params: &Rc<Params>,
    ) -> Vec<(CurveBN, CurveBN)> {
        let mut shares = Vec::with_capacity(num_shares as usize);
        // let mut coefficients_iter = coefficients.iter();
        for i in 1..num_shares + 1 {
            let i_bn = CurveBN::from_u32(i, &params);
            shares.push((i_bn, compute_polynomial(coefficients, i, params)));
        }
        shares
    }

    #[test]
    fn test_inv_mod() {
        let q = 101;
        let x = 3;
        let inv = mod_inv(x, q).unwrap();
        // assert_eq!(inv, 6);
        println!("{}^-1 mod {} = {:?}", x, q, inv);
    }

    #[test]
    fn test_swap_keypairs() {
        let params = new_standard_params();
        let alice = KeyPair::new(&params);
        let bob = KeyPair::new(&params);

        let (_alice2, bob2) = swap_keypairs(&alice, &bob);

        assert_eq!(alice.public_key().to_bytes(), bob2.public_key().to_bytes());
        assert_eq!(
            alice.private_key().to_bytes(),
            bob2.private_key().to_bytes()
        );
    }
    #[test]
    fn test_print_private_key() {
        let params = new_standard_params();
        let alice = KeyPair::new(&params);
        println!(
            "Alice private key (hex version): {}",
            vec_to_hex(&alice.private_key().to_bytes())
        );
    }

    #[test]
    fn test_random_coefficients() {
        let params = new_standard_params();
        let secret: u32 = 5;
        let secret_curve_bn = CurveBN::from_u32(secret, &params);
        let threshold: u32 = 5;
        let coefficients = random_coefficients(secret_curve_bn, threshold, &params);

        for i in 0..coefficients.len() {
            println!("coefficients[{}]: {:?}", i, coefficients[i]);
        }
    }

    #[test]
    fn test_compute_polynomial() {
        let params = new_standard_params();

        let threshold = 5;
        let secret = 5;
        let secret_curve_bn = CurveBN::from_u32(secret, &params);
        let coefficients = random_coefficients(secret_curve_bn, threshold, &params);

        // assert that if x=0 then y=coefficients[0]
        let y1 = compute_polynomial(&coefficients, 0, &params);
        assert_eq!(y1.eq(&coefficients[0]), true);

        // assert that if x=1 then y=sum(coefficients)
        let y2 = compute_polynomial(&coefficients, 1, &params);
        let mut sum: CurveBN = CurveBN::from_u32(0, &params);

        let mut coefficients_iter = coefficients.iter();
        for _ in 0..coefficients.len() {
            sum = &sum + coefficients_iter.next().unwrap();
        }
        assert_eq!(y2.eq(&sum), true);
    }

    #[test]
    fn test_privatekey_to_bn() {
        let params = new_standard_params();
        let alice = KeyPair::new(&params);
        let alice_bn = alice.private_key();
        println!("Alice private key (BN): {:?}", alice_bn);
    }

    #[test]
    fn test_create_shares() {
        let params = new_standard_params();
        let threshold = 5;
        let secret = 5;
        let secret_curve_bn = CurveBN::from_u32(secret, &params);
        let coefficients = random_coefficients(secret_curve_bn, threshold, &params);

        let shares = create_shares(&coefficients, 10, &params);
        println!("Shares: {:?}", shares);
    }

    #[test]
    fn test_compute_lagrange_coeff() {
        let params = new_standard_params();
        let threshold = 5;
        let secret = 5;
        let secret_curve_bn = CurveBN::from_u32(secret, &params);
        let coefficients = random_coefficients(secret_curve_bn, threshold, &params);

        let shares = create_shares(&coefficients, 10, &params);
        let lagrange_coefficients = compute_lagrange_coefficients(&shares, &params);
        println!("Lagrange coefficients: {:?}", lagrange_coefficients);
    }

    #[test]
    fn test_secret_sharing() {
        let params = new_standard_params();
        let threshold = 5;
        let secret_curve_bn = KeyPair::new(&params);
        let coefficients =
            random_coefficients(secret_curve_bn.private_key().clone(), threshold, &params);

        let shares = create_shares(&coefficients, threshold, &params);

        for share in shares.iter() {
            println!("Share: {:?}", share);
        }
        let computed_secret = compute_secret(&shares, &params);
        // print the secret and the computed secret
        println!("Secret: {:?}", secret_curve_bn.private_key().clone());
        println!("Computed secret: {:?}", computed_secret);
        assert_eq!(computed_secret.eq(secret_curve_bn.private_key()), true);
    }

    // #[test]
    // fn test_secret_sharing_refresh() {
    //     let params = new_standard_params();
    //     let threshold = 3;
    //     let num_parties = threshold + 1;

    //     // create secret
    //     let secret_curve_bn = KeyPair::new(&params);

    //     // create shares of secret
    //     let coefficients =
    //         random_coefficients(secret_curve_bn.private_key().clone(), threshold, &params);
    //     let shares = create_shares(&coefficients, num_parties, &params);

    //     // print shares
    //     for share in shares.iter() {
    //         println!("Share: {:?}", share);
    //     }

    //     // get new shares
    //     let shares_to_refresh = shares.iter().map(|x| x.1.clone()).collect::<Vec<CurveBN>>();
    //     let new_shares = key_refresh(&shares_to_refresh, threshold, &params);

    //     let mut new_share_for_secret: Vec<(CurveBN, CurveBN)> = vec![];
    //     for share in new_shares.iter() {
    //         println!("New Share: {:?}", share);
    //         let share_num = share.0.clone();
    //         let share_num_bn = CurveBN::from_u32(share_num as u32, &params);
    //         let share_bn = share.1.clone();

    //         new_share_for_secret.push((share_num_bn, share_bn));
    //     }
    //     let computed_secret = compute_secret(&new_share_for_secret, &params);

    //     println!("Secret: {:?}", secret_curve_bn.private_key().clone());
    //     println!("Computed secret: {:?}", computed_secret);
    //     assert_eq!(computed_secret.eq(secret_curve_bn.private_key()), true);
    //     // let new_shares = key_refresh(&share_to_refresh, threshold, &params);

    //     // let mut new_shares_to_refresh: Vec<(CurveBN, CurveBN)> = vec![];
    //     // for (num, share) in new_shares.iter() {
    //     //     let num_bn = CurveBN::from_u32(*num as u32, &params);
    //     //     new_shares_to_refresh.push((num_bn, share.clone()));
    //     // }
    //     // let computed_secret = compute_secret(&new_shares_to_refresh, &params);
    //     // // print the secret and the computed secret
    //     // println!("Secret: {:?}", secret_curve_bn.private_key().clone());
    //     // println!("Computed secret: {:?}", computed_secret);
    //     // assert_eq!(computed_secret.eq(secret_curve_bn.private_key()), true);
    // }

    // #[test]
    // fn test_key_refresh() {
    //     let N = 10;
    //     let params = new_standard_params();
    //     let threshold = 5;
    //     // let mod_q = 7919;

    //     let mut secret_vec: Vec<CurveBN> = vec![CurveBN::from_u32(0, &params); N];

    //     for i in 0..N {
    //         // create a random secret modulo mod_q for each user
    //         let mut alice = KeyPair::new(&params);
    //         let secret = alice.private_key().clone();
    //         secret_vec[i] = secret;
    //     }

    //     let res = key_refresh(&secret_vec, threshold, &params);

    //     // print the result
    //     println!("Result: {:?}", res);
    // }

    // #[test]
    // fn test_sum_curve_points() {
    //     // generate a new u32 random number
    //     let mut rng = rand::thread_rng();
    //     let random_number: u32 = rng.gen();
    //     let random_number2: u32 = rng.gen();

    //     // new standard params
    //     let params = new_standard_params();
    //     // coerce the u32 into CurveBN
    //     let curve_bn = CurveBN::from_u32(random_number, &params);
    //     let curve_bn2 = CurveBN::from_u32(random_number2, &params);

    //     println!("Is curve equal to itself? {:?}", curve_bn.eq(&curve_bn));

    //     let sum_points = &curve_bn + &curve_bn2;
    //     println!("Sum: {:?}", sum_points);

    //     let mul_points = &curve_bn * &curve_bn2;
    //     println!("Mul: {:?}", mul_points);
    // }

    // #[test]
    // fn test_generate_three_keys() {
    //     let params = new_standard_params();
    //     for i in 0..5 {
    //         let mut alice = KeyPair::new(&params);
    //         let alice_keys = alice.to_bytes();

    //         println!("Alice{} private key: {:?}", i, alice_keys.1);
    //         println!("Alice{} public key: {:?}", i, alice_keys.0);
    //     }
    // }

    // #[test]
    // fn test_unpack_params() {
    //     let params = new_standard_params();

    //     let group = params.group();
    //     let g_point = params.g_point();
    //     let order = params.order();
    //     let u_point = params.u_point();
    //     let field_order_size_in_bytes = params.field_order_size_in_bytes();
    //     let group_order_size_in_bytes = params.group_order_size_in_bytes();
    //     let ctx = params.ctx();

    //     // let params2 = Params::new(
    //     //     group,
    //     //     g_point,
    //     //     order,
    //     //     u_point,
    //     //     field_order_size_in_bytes,
    //     //     group_order_size_in_bytes,
    //     //     ctx,
    //     // );
    // }
}
