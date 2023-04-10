/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */


use super::EXPANDED_SPEND_BLAKE2_KEY;
use crate::keys::{
    PUBLIC_ADDRESS_SIZE,
    SaplingKey,
    ephemeral::EphemeralKeyPair,
    public_address::PublicAddress,
    view_keys::shared_secret,
};

use ironfish_zkp::constants::{
    PROOF_GENERATION_KEY_GENERATOR,
    SPENDING_KEY_GENERATOR,
    CRH_IVK_PERSONALIZATION,
    PUBLIC_KEY_GENERATOR,
};

use group::{Curve, GroupEncoding};
use jubjub::{ExtendedPoint};
use blake2b_simd::Params as Blake2b;
use blake2s_simd::Params as Blake2s;

#[test]
fn test_key_generation_and_construction() {
    let key = SaplingKey::generate_key();
    let key2 = SaplingKey::new(key.spending_key).unwrap();
    assert!(key.spending_key != [0; 32]);
    assert!(key2.spending_key == key.spending_key);
    assert!(key2.incoming_viewing_key.view_key == key.incoming_viewing_key.view_key);
}

#[test]
fn test_sk_to_ask() {
    let key = SaplingKey::generate_key();
    let sk = key.spending_key;
    let ask = key.spend_authorizing_key;

    let mut hasher = Blake2b::new()
        .hash_length(64)
        .personal(EXPANDED_SPEND_BLAKE2_KEY)
        .to_state();
    hasher.update(&sk);
    hasher.update(&[0]);

    let mut hash_result = [0; 64];
    hash_result[0..64].clone_from_slice(&hasher.finalize().as_ref()[0..64]);

    let computed_ask = jubjub::Fr::from_bytes_wide(&hash_result);

    assert_eq!(ask, computed_ask);
}

#[test]
fn test_sk_to_nsk() {
    let key = SaplingKey::generate_key();
    let sk = key.spending_key;
    let nsk = key.proof_authorizing_key;

    let mut hasher = Blake2b::new()
        .hash_length(64)
        .personal(EXPANDED_SPEND_BLAKE2_KEY)
        .to_state();
    hasher.update(&sk);
    hasher.update(&[1]);

    let mut hash_result = [0; 64];
    hash_result[0..64].clone_from_slice(&hasher.finalize().as_ref()[0..64]);

    let computed_nsk = jubjub::Fr::from_bytes_wide(&hash_result);

    assert_eq!(nsk, computed_nsk);
}

#[test]
fn test_sk_to_ovk() {
    let key = SaplingKey::generate_key();
    let sk = key.spending_key;
    let ovk = key.outgoing_viewing_key.view_key;

    let mut hasher = Blake2b::new()
        .hash_length(64)
        .personal(EXPANDED_SPEND_BLAKE2_KEY)
        .to_state();
    hasher.update(&sk);
    hasher.update(&[2]);

    let mut computed_ovk = [0; 32];
    computed_ovk[0..32].clone_from_slice(&hasher.finalize().as_ref()[0..32]);

    assert_eq!(ovk, computed_ovk);
}

#[test]
fn test_ask_to_ak() {
    let key = SaplingKey::generate_key();
    let ask = key.spend_authorizing_key;
    let ak = key.authorizing_key;

    let computed_ak = SPENDING_KEY_GENERATOR * ask;

    assert_eq!(ak, computed_ak);
}

#[test]
fn test_nsk_to_nk() {
    let key = SaplingKey::generate_key();
    let nsk = key.proof_authorizing_key;
    let nk = key.nullifier_deriving_key;

    let computed_nk = PROOF_GENERATION_KEY_GENERATOR * nsk;

    assert_eq!(nk, computed_nk);
}

#[test]
fn test_ak_nk_to_ivk() {
    let key = SaplingKey::generate_key();
    let ak = key.authorizing_key;
    let nk = key.nullifier_deriving_key;
    let ivk = key.incoming_viewing_key.view_key;

    let mut hasher = Blake2s::new()
        .hash_length(32)
        .personal(CRH_IVK_PERSONALIZATION)
        .to_state();
    hasher.update(&ak.to_bytes());
    hasher.update(&nk.to_bytes());

    let mut hash_result = [0; 32];
    hash_result.clone_from_slice(&hasher.finalize().as_ref()[0..32]);

    hash_result[31] &= 0b0000_0111;
    let computed_ivk = jubjub::Fr::from_bytes(&hash_result).unwrap();

    assert_eq!(ivk, computed_ivk);
}

#[test]
fn test_ivk_to_pk() {
    let key = SaplingKey::generate_key();
    let ivk = key.incoming_viewing_key.view_key;
    let pk = key.public_address().transmission_key;

    let computed_pk = PUBLIC_KEY_GENERATOR * ivk;

    assert_eq!(pk, computed_pk);
}

#[test]
fn test_diffie_hellman_shared_key() {
    let key1 = SaplingKey::generate_key();

    let address1 = key1.public_address();

    let key_pair = EphemeralKeyPair::new();
    let secret_key = key_pair.secret();
    let public_key = key_pair.public();

    let shared_secret1 = shared_secret(secret_key, &address1.transmission_key, public_key);
    let shared_secret2 = shared_secret(&key1.incoming_viewing_key.view_key, public_key, public_key);
    assert_eq!(shared_secret1, shared_secret2);
}

#[test]
fn test_diffie_hellman_shared_key_with_other_key() {
    let key1 = SaplingKey::generate_key();
    let secret_key_1 = &key1.incoming_viewing_key.view_key;
    let public_key_1 = &key1.public_address().transmission_key;

    let key2 = SaplingKey::generate_key();
    let secret_key_2 = &key2.incoming_viewing_key.view_key;
    let public_key_2 = &key2.public_address().transmission_key;

    let eph_keypair = EphemeralKeyPair::new();
    let eph_secret_key = eph_keypair.secret();
    let eph_public_key = eph_keypair.public();

    let shared_secret_1a = shared_secret(
        eph_secret_key,
        public_key_1,
        eph_public_key);
    let shared_secret_1b = shared_secret(
        secret_key_1,
        eph_public_key,
        eph_public_key);
    assert_eq!(shared_secret_1a, shared_secret_1b);

    let shared_secret_2a = shared_secret(
        eph_secret_key,
        public_key_2,
        eph_public_key,
    );
    let shared_secret_2b = shared_secret(
        secret_key_2,
        eph_public_key,
        eph_public_key,
    );
    assert_eq!(shared_secret_2a, shared_secret_2b);

    // shared secrets generated for an ephemeral key for different Sapling keys should be different
    assert_ne!(shared_secret_1a, shared_secret_2a);
}

#[test]
fn test_serialization() {
    let key = SaplingKey::generate_key();
    let mut serialized_key = [0; PUBLIC_ADDRESS_SIZE];
    key.write(&mut serialized_key[..])
        .expect("Should be able to serialize key");
    assert_ne!(serialized_key, [0; PUBLIC_ADDRESS_SIZE]);

    let read_back_key = SaplingKey::read(&mut serialized_key.as_ref())
        .expect("Should be able to load key from valid bytes");
    assert_eq!(
        read_back_key.incoming_view_key().view_key,
        key.incoming_view_key().view_key
    );

    let public_address = key.public_address();
    let mut serialized_address = [0; PUBLIC_ADDRESS_SIZE];
    public_address
        .write(&mut serialized_address[..])
        .expect("should be able to serialize address");

    let read_back_address: PublicAddress = PublicAddress::new(&serialized_address)
        .expect("Should be able to construct address from valid bytes");

    assert_eq!(
        ExtendedPoint::from(read_back_address.transmission_key).to_affine(),
        ExtendedPoint::from(public_address.transmission_key).to_affine()
    )
}

#[test]
fn test_hex_conversion() {
    let key = SaplingKey::generate_key();

    let hex = key.hex_spending_key();
    assert_eq!(hex.len(), 64);
    let second_key = SaplingKey::from_hex(&hex).unwrap();
    assert_eq!(second_key.spending_key, key.spending_key);

    let address = key.public_address();
    let hex = address.hex_public_address();
    assert_eq!(hex.len(), 2 * PUBLIC_ADDRESS_SIZE);
    let second_address = PublicAddress::from_hex(&hex).unwrap();
    assert_eq!(second_address, address);

    assert!(PublicAddress::from_hex("invalid").is_err());
}
