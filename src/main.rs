use umbral_rs::pre::*;
fn main() {
    let params = new_standard_params();
    let alice = KeyPair::new(&params);
    let signer = Signer::new(&params);
    let bob = KeyPair::new(&params);

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
}
