use umbral_rs::pre::*;

fn vec_to_hex(v: &[u8]) -> String {
    v.iter().map(|b| format!("{:02x}", b)).collect()
}

fn play(alice: &KeyPair) {
    let params = new_standard_params();
    // print alice public key
    println!("Alice public key: {:?}", alice.public_key().to_bytes());

    // print the hex version
    println!(
        "Alice public key (hex version): {}",
        vec_to_hex(&alice.public_key().to_bytes())
    );

    // create a copi of alice's public key and private key; then create a KeyPair from those
    let alice_copy = KeyPair::from_bytes(
        &alice.public_key().to_bytes(),
        &alice.private_key().to_bytes(),
        &params,
    )
    .unwrap();

    // assert that the public key and private key are the same
    assert_eq!(
        alice.public_key().to_bytes(),
        alice_copy.public_key().to_bytes()
    );
    assert_eq!(
        alice.private_key().to_bytes(),
        alice_copy.private_key().to_bytes()
    );

    // print the hex version of the copy
    println!(
        "Alice copy public key (hex version): {}",
        vec_to_hex(&alice_copy.public_key().to_bytes())
    );
}

// make a function that takes a two keypairs and swaps them
fn swap_keypairs(a: &KeyPair, b: &KeyPair) -> (KeyPair, KeyPair) {
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

fn main() {
    let params = new_standard_params();
    let mut alice = KeyPair::new(&params);
    let signer = Signer::new(&params);
    let mut bob = KeyPair::new(&params);

    let plaintext = b"Hello, umbral!".to_vec();
    let (ciphertext, mut capsule) = encrypt(&alice.public_key(), &plaintext).unwrap();

    capsule.set_correctness_keys(&alice.public_key(), &bob.public_key(), &signer.public_key());

    let threshold = 2;
    let nodes_number = 5;

    let kfrags = generate_kfrags(
        &alice,
        &bob.public_key(),
        threshold,
        nodes_number,
        &signer,
        KFragMode::DelegatingAndReceiving,
    )
    .unwrap();

    for kfrag in kfrags {
        let cfrag = reencrypt(&kfrag, &capsule, true, None, true).unwrap();
        capsule.attach_cfrag(&cfrag).unwrap();
    }

    let plaintext_bob = decrypt(ciphertext, &capsule, &bob, true).unwrap();
    assert_eq!(plaintext, plaintext_bob);
    println!("{:?}", String::from_utf8(plaintext_bob.to_owned()).unwrap());
    play(&alice);

    // print two blank lines
    println!();
    println!();
    // print that we swap the keypair, then swap them and print the result
    println!("Swapping keypairs");
    // print the current keypairs
    println!("Alice: {:?}", alice.public_key().to_bytes());
    println!("Bob: {:?}", bob.public_key().to_bytes());
    // swap the keypairs
    let (alice, bob) = swap_keypairs(&alice, &bob);
    println!("Alice: {:?}", alice.public_key().to_bytes());
    println!("Bob: {:?}", bob.public_key().to_bytes());
}
