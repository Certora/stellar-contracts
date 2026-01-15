use cvlr::{clog, cvlr_assert, cvlr_assume, cvlr_satisfy, nondet::*};
use cvlr_soroban::{nondet_address, nondet_bytes, nondet_bytes_n, nondet_vec};
use cvlr_soroban_derive::rule;
use soroban_sdk::{BytesN, Env, IntoVal, Vec, contracttype};
use crate::merkle_distributor::specs::merkle_distributor_sha256::MerkleDistributorSha256;
use crate::merkle_distributor::specs::merkle_distributor_sha256::Leaf;
use crate::merkle_distributor::specs::merkle_distributor_sha256::VerifierSha256;

#[rule]
// set_claimed panics if already claimed
// status: violation - bug?
pub fn set_claimed_panics_if_already_claimed(e: Env) {
    let index: u32 = nondet();
    let is_claimed_pre = MerkleDistributorSha256::is_claimed(&e, index);
    cvlr_assume!(is_claimed_pre);
    MerkleDistributorSha256::set_claimed(&e, index);
    cvlr_assert!(false);
}

#[rule]
// verify_and_set_claimed panics if already claimed
// status: verified
pub fn verify_and_set_claimed_panics_if_already_claimed(e: Env) {
    let leaf = Leaf::nondet();
    let index = leaf.index;
    let proof = nondet_vec();
    let is_claimed_pre = MerkleDistributorSha256::is_claimed(&e, index);
    cvlr_assume!(is_claimed_pre);
    MerkleDistributorSha256::verify_and_set_claimed(&e.clone(), leaf.clone(), proof);
    cvlr_assert!(false);
}

#[rule]
// verify_and_set_claimed panics if invalid proof
// status: violation - investigate
pub fn verify_and_set_claimed_panics_if_invalid_proof(e: Env) {
    let leaf = Leaf::nondet();
    let proof = nondet_vec();
    let root = MerkleDistributorSha256::get_root(&e);
    let (_, leaf_hash, _) = MerkleDistributorSha256::get_verification_args(&e, leaf.clone());
    let valid_proof = VerifierSha256::verify(&e, proof.clone(), root, leaf_hash);
    cvlr_assume!(!valid_proof);
    MerkleDistributorSha256::verify_and_set_claimed(&e.clone(), leaf.clone(), proof);
    cvlr_assert!(false);
}

#[rule]
// verify_with_index_and_set_claimed panics if already claimed
// status: verified
pub fn verify_with_index_and_set_claimed_panics_if_already_claimed(e: Env) {
    let leaf = Leaf::nondet();
    let index = leaf.index;
    let proof = nondet_vec();
    let is_claimed_pre = MerkleDistributorSha256::is_claimed(&e, index);
    cvlr_assume!(is_claimed_pre);
    MerkleDistributorSha256::verify_with_index_and_set_claimed(&e.clone(), leaf.clone(), proof);
    cvlr_assert!(false);
}

// todo invalid proof for verify_with_index_and_set_claimed