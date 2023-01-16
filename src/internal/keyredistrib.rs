pub use crate::internal::curve::{CurveBN, CurvePoint, Params};
pub use crate::internal::keys::*;
pub use crate::pre::*;
use modinverse::modinverse;
use openssl::bn::BigNumRef;
use rand::{thread_rng, Rng};
use std::collections::HashMap;

pub fn vec_to_hex(v: &[u8]) -> String {
    v.iter().map(|b| format!("{:02x}", b)).collect()
}

// const PARAMS: Rc<Params> = new_standard_params();

// convert private key to BN
fn priv_key_to_bn(priv_key: &Vec<u8>) {
    let params = new_standard_params();
    let curve_bn = CurveBN::from_bytes(&priv_key, &params).unwrap();
    // &curve_bn.bn()
}

// given number x and modulus q invert x mod q
fn mod_inv(x: i32, q: i32) -> Option<i32> {
    let x = x.rem_euclid(q);

    let res = modinverse(x, q);
    match res {
        Some(x) => res,
        None => panic!(
            "Error in mod_inv, modinverse returned None, q: {}, x: {}",
            q, x,
        ),
    }
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
    for i in 0..t {
        coefficients.push(CurveBN::rand_curve_bn(&params));
    }
    coefficients[0] = secret;
    coefficients
}

fn compute_polynomial(coefficients: &Vec<CurveBN>, x: u32, params: &Rc<Params>) -> CurveBN {
    let mut y: CurveBN = CurveBN::from_u32(0, &params);
    let mut x_pow: u32;
    let mut x_curve_bn: CurveBN;
    let mut y_curve_bn: CurveBN;
    let mut coefficients_iter = coefficients.iter();
    for i in 0..coefficients.len() {
        x_pow = x.pow(i as u32);
        x_curve_bn = CurveBN::from_u32(x_pow, &params);
        // y_curve_bn = coefficients_iter.next().unwrap();
        y = &y + &(coefficients_iter.next().unwrap() * &x_curve_bn);
    }
    y
}

fn create_shares(
    coefficients: &Vec<CurveBN>,
    num_shares: u32,
    params: &Rc<Params>,
) -> Vec<(CurveBN, CurveBN)> {
    let mut shares = Vec::with_capacity(num_shares as usize);
    // let mut coefficients_iter = coefficients.iter();
    for i in 1..num_shares + 1 {
        let mut i_bn = CurveBN::from_u32(i, &params);
        shares.push((i_bn, compute_polynomial(coefficients, i, params)));
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
    threshold: u32,
    params: &Rc<Params>,
) -> HashMap<usize, CurveBN> {
    let N = priv_key_vec.len();

    for i in 0..N - 1 {
        println!("priv_key_vec[{}]: {:?}", i, priv_key_vec[i]);
    }

    let mut shares_dict_for_others = HashMap::new();
    let mut priv_key_vec_iter = priv_key_vec.iter();
    for i in 0..N - 1 {
        let mut coefficients = random_coefficients(
            priv_key_vec_iter.next().unwrap().clone(),
            threshold,
            &params,
        );
        let mut shares = create_shares(&coefficients, N as u32, &params);
        shares_dict_for_others.insert(i, shares);
    }

    // shares_dict_for_others

    let mut curr_share: &(CurveBN, CurveBN);
    let mut new_priv_keys = HashMap::new();
    for i in 0..N - 1 {
        let mut share_sum = CurveBN::from_u32(0, &params);
        let mut shares_dict_for_others_iter = shares_dict_for_others[&i].iter();
        for j in 0..N - 1 {
            let mut interim_share = shares_dict_for_others_iter.next().unwrap();
            if i != j {
                curr_share = interim_share;
                share_sum = &share_sum + &curr_share.1;
            }
        }
        new_priv_keys.insert(i, share_sum);
    }

    new_priv_keys
}
#[cfg(test)]
mod tests {
    use super::*;
    // pub use crate::internal::keyredistrib::*;
    // use crate::pre::*;

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
        let computed_secret = compute_secret(&shares, &params);
        // print the secret and the computed secret
        println!("Secret: {:?}", secret_curve_bn.private_key().clone());
        println!("Computed secret: {:?}", computed_secret);
        assert_eq!(computed_secret.eq(secret_curve_bn.private_key()), true);
    }

    #[test]
    fn test_key_refresh() {
        let N = 10;
        let params = new_standard_params();
        let threshold = 5;
        // let mod_q = 7919;

        let mut secret_vec: Vec<CurveBN> = vec![CurveBN::from_u32(0, &params); N];

        for i in 0..N {
            // create a random secret modulo mod_q for each user
            let mut alice = KeyPair::new(&params);
            let secret = alice.private_key().clone();
            secret_vec[i] = secret;
        }

        let res = key_refresh(&secret_vec, threshold, &params);

        // print the result
        println!("Result: {:?}", res);
    }

    #[test]
    fn test_sum_curve_points() {
        // generate a new u32 random number
        let mut rng = rand::thread_rng();
        let random_number: u32 = rng.gen();
        let random_number2: u32 = rng.gen();

        // new standard params
        let params = new_standard_params();
        // coerce the u32 into CurveBN
        let curve_bn = CurveBN::from_u32(random_number, &params);
        let curve_bn2 = CurveBN::from_u32(random_number2, &params);

        println!("Is curve equal to itself? {:?}", curve_bn.eq(&curve_bn));

        let sum_points = &curve_bn + &curve_bn2;
        println!("Sum: {:?}", sum_points);

        let mul_points = &curve_bn * &curve_bn2;
        println!("Mul: {:?}", mul_points);
    }

    #[test]
    fn test_generate_three_keys() {
        let params = new_standard_params();
        for i in 0..5 {
            let mut alice = KeyPair::new(&params);
            let alice_keys = alice.to_bytes();

            println!("Alice{} private key: {:?}", i, alice_keys.1);
            println!("Alice{} public key: {:?}", i, alice_keys.0);
        }
    }

    #[test]
    fn test_unpack_params() {
        let params = new_standard_params();

        let group = params.group();
        let g_point = params.g_point();
        let order = params.order();
        let u_point = params.u_point();
        let field_order_size_in_bytes = params.field_order_size_in_bytes();
        let group_order_size_in_bytes = params.group_order_size_in_bytes();
        let ctx = params.ctx();

        // let params2 = Params::new(
        //     group,
        //     g_point,
        //     order,
        //     u_point,
        //     field_order_size_in_bytes,
        //     group_order_size_in_bytes,
        //     ctx,
        // );
    }
}
