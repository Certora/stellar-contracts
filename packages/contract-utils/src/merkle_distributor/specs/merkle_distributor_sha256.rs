use cvlr::nondet::*;
use soroban_sdk::{contracttype, BytesN, Env, IntoVal, Vec};

use crate::{
    crypto::{merkle::Verifier, sha256::Sha256},
    merkle_distributor::{IndexableLeaf, MerkleDistributor},
};

pub type MerkleDistributorSha256 = MerkleDistributor<Sha256>;
pub type VerifierSha256 = Verifier<Sha256>;

#[contracttype]
#[derive(Clone)]
pub struct Leaf {
    pub index: u32,
}

impl Nondet for Leaf {
    fn nondet() -> Self {
        Leaf { index: u32::nondet() }
    }
}

impl IndexableLeaf for Leaf {
    fn index(&self) -> u32 {
        self.index
    }
}
