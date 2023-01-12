pub use crate::internal::keys::*;
pub use crate::pre::*;
use modinverse::modinverse;
use rand::{thread_rng, Rng};
use std::collections::HashMap;

pub fn vec_to_hex(v: &[u8]) -> String {
    v.iter().map(|b| format!("{:02x}", b)).collect()
}

// convert private key to BN
fn priv_key_to_bn(priv_key: &Vec<u8>) -> CurveBN {
    let params = new_standard_params();
    CurveBN::from_bytes(&priv_key, &params).unwrap()
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

fn random_coefficients(secret: i32, t: i32, q: i32) -> Vec<i32> {
    let mut rng = thread_rng();
    let mut coefficients = vec![0; t as usize];
    for i in 0..t {
        coefficients[i as usize] = rng.gen_range(0..q);
    }
    coefficients[0] = secret;
    coefficients
}

fn compute_polynomial(coefficients: &Vec<i32>, x: i32, q: i32) -> i32 {
    let mut y = 0;
    for i in 0..coefficients.len() {
        y += coefficients[i] * x.pow(i as u32);
    }
    y % q
}

fn create_shares(coefficients: &Vec<i32>, num_shares: i32, q: i32) -> Vec<(i32, i32)> {
    let mut shares = vec![];
    for i in 1..num_shares + 1 {
        shares.push((i, compute_polynomial(coefficients, i, q)));
    }
    shares
}

// given t shares, compute lagrange coefficients
fn compute_lagrange_coefficients(shares: &Vec<(i32, i32)>, q: i32) -> Vec<i32> {
    let mut coefficients = vec![];
    for i in 0..shares.len() {
        let mut numerator = 1;
        let mut denominator = 1;
        for j in 0..shares.len() {
            if i != j {
                numerator *= -shares[j].0;
                numerator = numerator.rem_euclid(q);
                denominator *= shares[i].0 - shares[j].0;
                denominator = denominator.rem_euclid(q);
            }
        }
        coefficients.push(
            ((numerator * shares[i].1).rem_euclid(q) * mod_inv(denominator, q).unwrap())
                .rem_euclid(q),
        );
    }
    coefficients
}

fn key_refresh(priv_key_vec: &Vec<i32>, threshold: i32, q: i32) -> HashMap<usize, i32> {
    let N = priv_key_vec.len();

    for i in 0..N - 1 {
        println!("priv_key_vec[{}]: {}", i, priv_key_vec[i]);
    }

    let mut shares_dict_for_others = HashMap::new();
    for i in 0..N - 1 {
        let mut coefficients = random_coefficients(priv_key_vec[i], threshold, q);
        let mut shares = create_shares(&coefficients, N as i32, q);
        shares_dict_for_others.insert(i, shares);
    }

    // shares_dict_for_others

    let mut curr_share = (0, 0);
    let mut share_sum = 0;
    let mut new_priv_keys = HashMap::new();
    for i in 0..N - 1 {
        for j in 0..N - 1 {
            if i != j {
                curr_share = shares_dict_for_others[&i][j];
                share_sum += curr_share.1;
                share_sum = share_sum.rem_euclid(q);
            }
        }
        new_priv_keys.insert(i, share_sum);
    }

    new_priv_keys

    // let mut new_priv_key_vec = vec![0; N];
    // for i in 0..N - 1 {
    //     let sum_inter = 0;
    //     for _ in 0..N - 1 {
    //         sum_inter += shares_dict_for_owner[i]
    //     }
    //     new_priv_key_vec[i] = compute_secret(&shares_dict_for_owner[i], q);
    // }
}

// given t shares, compute secret
fn compute_secret(shares: &Vec<(i32, i32)>, q: i32) -> i32 {
    let coefficients = compute_lagrange_coefficients(shares, q);
    let mut secret = 0;

    for i in 0..coefficients.len() {
        secret += coefficients[i];
    }

    secret % q
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
        let secret = 5;
        let coefficients = random_coefficients(secret, 10, 101);
        println!("Coefficients: {:?}", coefficients);
    }

    #[test]
    fn test_compute_polynomial() {
        let threshold = 5;
        let mod_q = 101;
        let secret = 5;
        let coefficients = random_coefficients(secret, threshold, mod_q);

        // assert that if x=0 then y=coefficients[0]
        let y = compute_polynomial(&coefficients, 0, mod_q);
        assert_eq!(y, coefficients[0]);

        // assert that if x=1 then y=sum(coefficients)
        let y = compute_polynomial(&coefficients, 1, mod_q);
        let mut sum = 0;
        for i in 0..coefficients.len() {
            sum += coefficients[i];
        }
        assert_eq!(y, sum % mod_q);
    }

    #[test]
    fn test_privatekey_to_bn() {
        let params = new_standard_params();
        let alice = KeyPair::new(&params);
        let alice_bn = priv_key_to_bn(&alice.private_key().to_bytes());
        println!("Alice private key (BN): {:?}", alice_bn.bn());
    }

    #[test]
    fn test_create_shares() {
        let threshold = 5;
        let mod_q = 101;
        let secret = 5;
        let coefficients = random_coefficients(secret, threshold, mod_q);
        let shares = create_shares(&coefficients, 10, mod_q);
        println!("Shares: {:?}", shares);
    }

    #[test]
    fn test_compute_lagrange_coeff() {
        let threshold = 5;
        let mod_q = 101;
        let secret = 5;
        let coefficients = random_coefficients(secret, threshold, mod_q);
        let shares = create_shares(&coefficients, 10, mod_q);
        let lagrange_coefficients = compute_lagrange_coefficients(&shares, mod_q);
        println!("Lagrange coefficients: {:?}", lagrange_coefficients);
    }

    #[test]
    fn test_secret_sharing() {
        let threshold = 5;
        let mod_q = 101;
        let secret = 5;

        let coefficients = random_coefficients(secret, threshold, mod_q);
        let shares = create_shares(&coefficients, 10, mod_q);
        let computed_secret = compute_secret(&shares, mod_q);
        // print the secret and the computed secret
        println!("Secret: {}", secret);
        println!("Computed secret: {}", computed_secret);
        assert_eq!(computed_secret, secret);
    }

    #[test]
    fn test_a_dictionary() {
        let mut test_dict = HashMap::new();
        test_dict.insert(0, vec![1, 2, 3]);
        test_dict.insert(1, vec![4, 5, 6]);
        test_dict.insert(2, vec![7, 8, 9]);

        println!("test_dict: {:?}", test_dict[&0]);
    }

    #[test]
    fn test_key_refresh() {
        let N = 10;
        let threshold = 5;
        let mod_q = 7919;

        let mut secret_vec = vec![0; N];

        for i in 0..N {
            // create a random secret modulo mod_q for each user
            let secret = rand::thread_rng().gen_range(0..mod_q);
            secret_vec[i] = secret;
        }

        let res = key_refresh(&secret_vec, threshold, mod_q);

        // print the result
        println!("Result: {:?}", res);
    }
}
