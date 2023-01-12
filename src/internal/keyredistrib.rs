pub use crate::internal::keys::*;
pub use crate::pre::*;
use rand::{thread_rng, Rng};

pub fn vec_to_hex(v: &[u8]) -> String {
    v.iter().map(|b| format!("{:02x}", b)).collect()
}

// convert private key to BN
fn priv_key_to_bn(priv_key: &Vec<u8>) -> CurveBN {
    let params = new_standard_params();
    CurveBN::from_bytes(&priv_key, &params).unwrap()
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

#[cfg(test)]
mod tests {
    use super::*;
    // pub use crate::internal::keyredistrib::*;
    use crate::pre::*;

    #[test]
    fn test_swap_keypairs() {
        let params = new_standard_params();
        let alice = KeyPair::new(&params);
        let bob = KeyPair::new(&params);

        let (alice2, bob2) = swap_keypairs(&alice, &bob);

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
}
