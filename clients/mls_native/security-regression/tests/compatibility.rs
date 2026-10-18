//! Exercise the exact advisory surfaces as well as provider interoperability.
//! All keys and seeds are synthetic test inputs, never production material.

use hpke_rs::{Hpke, Mode};
use hpke_rs_crypto::{
    types::{AeadAlgorithm, KdfAlgorithm, KemAlgorithm},
    HpkeCrypto,
};
use hpke_rs_libcrux::HpkeLibcrux;
use hpke_rs_rust_crypto::HpkeRustCrypto;
use libcrux_kem::{key_gen_derand, Algorithm, Ct, PrivateKey, PublicKey};

fn hybrid_keys(algorithm: Algorithm) -> (PrivateKey, PublicKey) {
    match algorithm {
        Algorithm::XWingKemDraft06 => {
            key_gen_derand(algorithm, &[42; 32]).expect("valid synthetic XWing seed")
        }
        Algorithm::X25519MlKem768Draft00 => {
            // Build this older draft's valid wire keys from its two components.
            // Its unrelated key_gen_derand passes one seed to both algorithms
            // despite their different required seed lengths (64 versus 32).
            let (ml_private, ml_public) = key_gen_derand(Algorithm::MlKem768, &[42; 64])
                .expect("valid synthetic ML-KEM seed");
            let (dh_private, dh_public) = key_gen_derand(Algorithm::X25519, &[43; 32])
                .expect("valid synthetic X25519 seed");
            let private = [ml_private.encode(), dh_private.encode()].concat();
            let public = [ml_public.encode(), dh_public.encode()].concat();
            (
                PrivateKey::decode(algorithm, &private).expect("valid hybrid private wire key"),
                PublicKey::decode(algorithm, &public).expect("valid hybrid public wire key"),
            )
        }
        _ => unreachable!("only the two affected hybrid algorithms are tested"),
    }
}

fn reject_truncated_keys(algorithm: Algorithm) {
    let (private, public) = hybrid_keys(algorithm);
    let private_bytes = private.encode();
    let public_bytes = public.encode();
    // Every shorter buffer length must return an error. A panic fails this
    // ordinary Rust test; no catch_unwind or error suppression hides it.
    for length in 0..private_bytes.len() {
        assert!(
            PrivateKey::decode(algorithm, &private_bytes[..length]).is_err(),
            "{algorithm:?} accepted truncated private key length {length}"
        );
    }
    for length in 0..public_bytes.len() {
        assert!(
            PublicKey::decode(algorithm, &public_bytes[..length]).is_err(),
            "{algorithm:?} accepted truncated public key length {length}"
        );
    }
    assert!(PrivateKey::decode(algorithm, &private_bytes).is_ok());
    assert!(PublicKey::decode(algorithm, &public_bytes).is_ok());
}

#[test]
fn rustsec_2026_0331_xwing_truncated_keys_return_errors() {
    reject_truncated_keys(Algorithm::XWingKemDraft06);
}

#[test]
fn rustsec_2026_0331_x25519_mlkem_truncated_keys_return_errors() {
    reject_truncated_keys(Algorithm::X25519MlKem768Draft00);
}

fn reject_short_encapsulation_seeds(algorithm: Algorithm) {
    let (private, public) = hybrid_keys(algorithm);
    for length in 0..64 {
        assert!(
            public.encapsulate_derand(&vec![7; length]).is_err(),
            "{algorithm:?} accepted invalid encapsulation seed length {length}"
        );
    }
    for length in [65, 96] {
        assert!(public.encapsulate_derand(&vec![7; length]).is_err());
    }
    let (shared, ciphertext) = public
        .encapsulate_derand(&[7; 64])
        .expect("the full encapsulation seed remains compatible");
    let wire = ciphertext.encode();
    let decoded = Ct::decode(algorithm, &wire).expect("ciphertext roundtrip");
    let recovered = decoded.decapsulate(&private).expect("hybrid decapsulation");
    assert_eq!(shared.encode(), recovered.encode());
}

#[test]
fn rustsec_2026_0330_xwing_short_seeds_return_errors_and_valid_kem_roundtrips() {
    reject_short_encapsulation_seeds(Algorithm::XWingKemDraft06);
}

#[test]
fn rustsec_2026_0330_x25519_mlkem_short_seeds_return_errors_and_valid_kem_roundtrips() {
    reject_short_encapsulation_seeds(Algorithm::X25519MlKem768Draft00);
}

#[test]
fn patched_hpke_provider_rejects_short_xwing_public_and_private_keys() {
    let algorithm = KemAlgorithm::XWingDraft06;
    let mut rng = HpkeLibcrux::prng();
    let (public, private) = HpkeLibcrux::kem_key_gen(algorithm, &mut rng)
        .expect("optional provider can generate hybrid keys");
    for length in [0, 1, 31, 32, 100, public.len() - 1] {
        assert!(HpkeLibcrux::kem_encaps(algorithm, &public[..length], &mut rng).is_err());
    }
    let (shared, ciphertext) = HpkeLibcrux::kem_encaps(algorithm, &public, &mut rng)
        .expect("optional provider encapsulation");
    for length in 0..private.len() {
        assert!(HpkeLibcrux::kem_decaps(algorithm, &ciphertext, &private[..length]).is_err());
    }
    assert_eq!(
        shared,
        HpkeLibcrux::kem_decaps(algorithm, &ciphertext, &private)
            .expect("optional provider decapsulation")
    );
}

fn cross_provider<Sender: HpkeCrypto + 'static, Recipient: HpkeCrypto + 'static>() {
    for (kem, aead) in [
        (KemAlgorithm::DhKem25519, AeadAlgorithm::Aes128Gcm),
        (KemAlgorithm::DhKemP256, AeadAlgorithm::ChaCha20Poly1305),
    ] {
        let mut sender = Hpke::<Sender>::new(Mode::Base, kem, KdfAlgorithm::HkdfSha256, aead);
        let mut recipient = Hpke::<Recipient>::new(Mode::Base, kem, KdfAlgorithm::HkdfSha256, aead);
        let (private, public) = recipient
            .generate_key_pair()
            .expect("recipient keys")
            .into_keys();
        let info = b"SCAP provider compatibility";
        let aad = b"group=synthetic;epoch=1";
        let plaintext = b"synthetic compatibility message";
        let (enc, ciphertext) = sender
            .seal(&public, info, aad, plaintext, None, None, None)
            .expect("cross-provider encryption");
        assert_eq!(
            recipient
                .open(&enc, &private, info, aad, &ciphertext, None, None, None)
                .expect("cross-provider decryption"),
            plaintext
        );
        assert!(
            recipient
                .open(
                    &enc,
                    &private,
                    info,
                    b"wrong epoch",
                    &ciphertext,
                    None,
                    None,
                    None
                )
                .is_err(),
            "AAD changes must fail authentication"
        );
        let mut tampered = ciphertext.clone();
        tampered[0] ^= 1;
        assert!(
            recipient
                .open(&enc, &private, info, aad, &tampered, None, None, None)
                .is_err(),
            "ciphertext changes must fail authentication"
        );
    }
}

#[test]
fn patched_libcrux_sends_to_the_production_rustcrypto_provider() {
    cross_provider::<HpkeLibcrux, HpkeRustCrypto>();
}

#[test]
fn production_rustcrypto_sends_to_the_patched_libcrux_provider() {
    cross_provider::<HpkeRustCrypto, HpkeLibcrux>();
}
