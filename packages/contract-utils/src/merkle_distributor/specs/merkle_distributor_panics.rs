use cvlr::{clog, cvlr_assert, cvlr_assume, cvlr_satisfy, nondet::*};
use cvlr_soroban::{nondet_address, nondet_bytes, nondet_bytes_n, nondet_vec};
use cvlr_soroban_derive::rule;
use soroban_sdk::{BytesN, Env, IntoVal, Vec, contracttype};
use crate::merkle_distributor::specs::merkle_distributor_sha256::MerkleDistributorSha256;
use crate::merkle_distributor::specs::merkle_distributor_sha256::Leaf;

// property: P-XX. MerkleDistributor-Panics.
// description: MerkleDistributor functions panic in all appropriate cases.
// status: violated

#[rule]
// set_claimed panics if already claimed
// status: violated
// link: https://prover.certora.com/output/5771024/6a3483107de148b3b94cbaf918c1a8e5/?anonymousKey=bdd4242775676bd7dd86fdd7155797ac2ee17925
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
// link: https://prover.certora.com/output/5771024/6a3483107de148b3b94cbaf918c1a8e5/?anonymousKey=bdd4242775676bd7dd86fdd7155797ac2ee17925
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
// verify_with_index_and_set_claimed panics if already claimed
// status: verified
// link: https://prover.certora.com/output/5771024/6a3483107de148b3b94cbaf918c1a8e5/?anonymousKey=bdd4242775676bd7dd86fdd7155797ac2ee17925
pub fn verify_with_index_and_set_claimed_panics_if_already_claimed(e: Env) {
    let leaf = Leaf::nondet();
    let index = leaf.index;
    let proof = nondet_vec();
    let is_claimed_pre = MerkleDistributorSha256::is_claimed(&e, index);
    cvlr_assume!(is_claimed_pre);
    MerkleDistributorSha256::verify_with_index_and_set_claimed(&e.clone(), leaf.clone(), proof);
    cvlr_assert!(false);
}
