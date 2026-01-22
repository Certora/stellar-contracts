use cvlr::{cvlr_assert, cvlr_assume, cvlr_satisfy, nondet::Nondet};
use cvlr_soroban::nondet_address;
use cvlr_soroban_derive::rule;
use soroban_sdk::Env;

use crate::pausable::{
    pause, paused, specs::pausable_contract::PausableContract, storage::PausableStorageKey,
    Pausable,
};

// property: P-11. Pausable-Non-Panics.
// description: Pausable functions do not under appropriate assumptions.
// status: verified

// These rules require the prover arg "prover_args": ["-trapAsAssert true"] to
// consider also panicking paths.

#[rule]
// if unpaused pause does not panic
// status: verified
// link: https://prover.certora.com/output/40748/8503bf7445624554b26ff046f2e6f413/?anonymousKey=f347db4b63b3cc756554049dea0f2e7e4c806e25
pub fn pause_non_panic(e: Env) {
    // storage set up
    let bool = bool::nondet();
    e.storage().instance().set(&PausableStorageKey::Paused, &bool);
    let paused_pre = PausableContract::paused(&e);
    cvlr_assume!(!paused_pre);
    let caller = nondet_address();
    PausableContract::pause(&e, caller);
    cvlr_assert!(true);
}

#[rule]
// if paused unpause does not panic
// status: verified
// link: https://prover.certora.com/output/40748/8503bf7445624554b26ff046f2e6f413/?anonymousKey=f347db4b63b3cc756554049dea0f2e7e4c806e25
pub fn unpause_non_panic(e: Env) {
    // storage set up
    let bool = bool::nondet();
    e.storage().instance().set(&PausableStorageKey::Paused, &bool);
    let paused_pre = PausableContract::paused(&e);
    cvlr_assume!(paused_pre);
    let caller = nondet_address();
    PausableContract::unpause(&e, caller);
    cvlr_assert!(true);
}

#[rule]
// if unpaused when_not_paused_func does not panic
// status: verified
// link: https://prover.certora.com/output/40748/8503bf7445624554b26ff046f2e6f413/?anonymousKey=f347db4b63b3cc756554049dea0f2e7e4c806e25
pub fn when_not_paused_non_panic(e: Env) {
    // storage set up
    let bool = bool::nondet();
    e.storage().instance().set(&PausableStorageKey::Paused, &bool);
    let paused_pre = PausableContract::paused(&e);
    cvlr_assume!(!paused_pre);
    PausableContract::when_not_paused_func(&e);
    cvlr_assert!(true);
}

#[rule]
// if paused when_paused_func does not panic
// status: verified
// link: https://prover.certora.com/output/40748/8503bf7445624554b26ff046f2e6f413/?anonymousKey=f347db4b63b3cc756554049dea0f2e7e4c806e25
pub fn when_paused_non_panic(e: Env) {
    // storage set up
    let bool = bool::nondet();
    e.storage().instance().set(&PausableStorageKey::Paused, &bool);
    let paused_pre = PausableContract::paused(&e);
    cvlr_assume!(paused_pre);
    PausableContract::when_paused_func(&e);
    cvlr_assert!(true);
}