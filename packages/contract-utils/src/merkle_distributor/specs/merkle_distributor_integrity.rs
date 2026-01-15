use cvlr::{clog, cvlr_assert, cvlr_satisfy, nondet::*};
use cvlr_soroban::{nondet_address, nondet_bytes, nondet_bytes_n, nondet_vec};
use cvlr_soroban_derive::rule;
use soroban_sdk::{BytesN, Env, IntoVal, Vec, contracttype};
use crate::merkle_distributor::specs::merkle_distributor_sha256::MerkleDistributorSha256;
use crate::merkle_distributor::specs::merkle_distributor_sha256::Leaf;

#[rule]
// set root sets the root hash in storage
// status: verified
pub fn set_root_integrity(e: Env) {
    let root_hash = nondet_bytes_n();
    MerkleDistributorSha256::set_root(&e, root_hash.clone());
    let root = MerkleDistributorSha256::get_root(&e);
    cvlr_assert!(root == root_hash);
}

#[rule]
// set_claimed set the claimed status of an index to true
// status: verified
pub fn set_claimed_integrity(e: Env) {
    let index: u32 = nondet();
    MerkleDistributorSha256::set_claimed(&e, index);
    let claimed = MerkleDistributorSha256::is_claimed(&e, index);
    cvlr_assert!(claimed);
}

#[rule]
// verify_and_set_claimed sets the claimed status of an index to true
// status: verified
pub fn verify_and_set_claimed_integrity(e: Env) {
    let index: u32 = nondet();
    let leaf = Leaf::nondet();
    let proof = nondet_vec();
    MerkleDistributorSha256::verify_and_set_claimed(&e.clone(), leaf.clone(), proof);
    let claimed = MerkleDistributorSha256::is_claimed(&e, leaf.index);
    cvlr_assert!(claimed);
}

#[rule]
// verify_with_index_and_set_claimed sets the claimed status of an index to true
// status: verified
pub fn verify_with_index_and_set_claimed_integrity(e: Env) {
    let index: u32 = nondet();
    let leaf = Leaf::nondet();
    let proof = nondet_vec();
    MerkleDistributorSha256::verify_with_index_and_set_claimed(&e.clone(), leaf.clone(), proof);
    let claimed = MerkleDistributorSha256::is_claimed(&e, leaf.index);
    cvlr_assert!(claimed);
}

