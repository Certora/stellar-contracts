use cvlr::{nondet::*};
use crate::{
    crypto::sha256::Sha256,
    merkle_distributor::{IndexableLeaf, MerkleDistributor},
};
use crate::crypto::merkle::Verifier;
use soroban_sdk::{BytesN, Env, IntoVal, Vec, contracttype};

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

