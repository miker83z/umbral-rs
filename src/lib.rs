#![cfg_attr(feature = "unstable", feature(test))]

//! umbral is the implementation of the
//! [Umbral](https://github.com/nucypher/umbral-doc/blob/master/umbral-doc.pdf)
//! threshold proxy re-encryption scheme, built with Rust taking as reference
//! the [Python](https://github.com/nucypher/pyUmbral) version createdby the
//! Umbral authors.
//!
//! Umbral is the implementation of a Proxy Re-Encryption scheme, in which a
//! data holder can delegate decryption rights to a data consumer for any
//! encrypted text intended for him/her. It is carried out through a
//! re-encryption process performed by a series of semi-trusted proxies. When
//! a threshold of these proxies participates by performing the re-encryption
//! and creating some shares, the consumer is able to combine these independent
//! re-encryption shares and decrypt the original message using his private key.
//!
//! ## Encrypt/Decrypt Example
//! ```rust
//! use umbral::pre::*;
//!
//! let params = new_standard_params();
//! let alice = KeyPair::new(&params);
//! let signer = Signer::new(&params);
//! let bob = KeyPair::new(&params);
//!
//! let plaintext = b"Hello, umbral!".to_vec();
//! let (ciphertext, mut capsule) = encrypt(&alice.public_key(), &plaintext).unwrap();
//!
//! capsule.set_correctness_keys(&alice.public_key(), &bob.public_key(), &signer.public_key());
//!
//! let threshold = 2;
//! let nodes_number = 5;
//!
//! let kfrags = generate_kfrags(
//!   &alice,
//!   &bob.public_key(),
//!   threshold,
//!   nodes_number,
//!   &signer,
//!   KFragMode::DelegatingAndReceiving,
//! ).unwrap();
//!
//! for kfrag in kfrags {
//!   let cfrag = reencrypt(&kfrag, &capsule, true, None, true).unwrap();
//!   capsule.attach_cfrag(&cfrag).unwrap();
//! }
//!
//! let plaintext_bob = decrypt(ciphertext, &capsule, &bob, true).unwrap();
//! assert_eq!(plaintext, plaintext_bob);
//! println!("{:?}", String::from_utf8(plaintext_bob.to_owned()).unwrap());
//!  ```

mod internal;
pub mod pre;
