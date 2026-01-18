use cvlr::{clog, cvlr_assert, cvlr_satisfy};
use cvlr_soroban::nondet_address;
use cvlr_soroban_derive::rule;
use soroban_sdk::Env;

use crate::pausable::{pause, paused, specs::pausable_contract::PausableContract, Pausable};

// property: P-09. Pausable-Integrity.
// description: Pausable functions change state as expected.
// status: verified

#[rule]
// after call to pause the contract is paused
// status: verified
// link: https://prover.certora.com/output/40748/2d7f026a025f491282b575e5762b2f61/?anonymousKey=f8785238cc6281a5b844bbfcbf55b78d0b5d4772
pub fn pause_integrity(e: Env) {
    let caller = nondet_address();
    PausableContract::pause(&e, caller);
    let paused_post = PausableContract::paused(&e);
    cvlr_assert!(paused_post);
}

#[rule]
// after call to unpause the contract is not paused
// status: verified
// link: https://prover.certora.com/output/40748/2d7f026a025f491282b575e5762b2f61/?anonymousKey=f8785238cc6281a5b844bbfcbf55b78d0b5d4772
pub fn unpause_integrity(e: Env) {
    let caller = nondet_address();
    PausableContract::unpause(&e, caller);
    let paused_post = PausableContract::paused(&e);
    cvlr_assert!(!paused_post);
}
