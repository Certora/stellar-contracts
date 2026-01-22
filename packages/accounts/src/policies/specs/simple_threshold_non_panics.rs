use core::task::Context;

use cvlr::{
    clog, cvlr_assert, cvlr_assume, cvlr_satisfy,
    nondet::{self, Nondet},
};
use cvlr_soroban::{is_auth, nondet_address};
use cvlr_soroban_derive::rule;
use soroban_sdk::{Address, Env, Vec};

use crate::{
    policies::{
        simple_threshold::{
            can_enforce, enforce, get_threshold, install, set_threshold, uninstall,
            SimpleThresholdAccountParams, SimpleThresholdStorageKey,
        },
    },
    smart_account::{specs::nondet::nondet_signers_vec, ContextRule, Signer},
};

// property: P-XX. SimpleThreshold-Non-Panics.
// description: SimpleThreshold functions do not panic under appropriate assumptions.
// status: verified

fn storage_setup_threshold(e: Env, ctx_rule_id: u32, account_id: Address) {
    let threshold: u32 = u32::nondet();
    let key = SimpleThresholdStorageKey::AccountContext(account_id.clone(), ctx_rule_id);
    e.storage().persistent().set(&key, &threshold);
    clog!(threshold);
}

// These rules require the prover arg "prover_args": ["-trapAsAssert true"] to
// consider also panicking paths.

#[rule]
// if storage is setup, setting a valid threshold and account_id is auth, then set_threshold does not panic
// status: verified
// link: https://prover.certora.com/output/40748/77b92956f46c47e980883b164ee2d81c/?anonymousKey=9035f9923a813c045c3556dc873cf1cf402e49db
pub fn set_threshold_non_panic(e: Env) {
    let threshold: u32 = u32::nondet();
    let ctx_rule: ContextRule = ContextRule::nondet();
    let account_id = nondet_address();
    cvlr_assume!(is_auth(account_id.clone()));
    storage_setup_threshold(e.clone(), ctx_rule.id, account_id.clone());
    cvlr_assume!(threshold != 0 && threshold <= ctx_rule.signers.len());
    clog!(threshold);
    clog!(ctx_rule.signers.len());
    set_threshold(&e, threshold, &ctx_rule, &account_id);
    cvlr_assert!(true);
}

#[rule]
// if storage is setup, threshold exists, then get_threshold does not panic
// status: verified
// link: https://prover.certora.com/output/40748/77b92956f46c47e980883b164ee2d81c/?anonymousKey=9035f9923a813c045c3556dc873cf1cf402e49db
pub fn get_threshold_non_panic(e: Env) {
    let ctx_rule_id: u32 = u32::nondet();
    let account_id = nondet_address();
    storage_setup_threshold(e.clone(), ctx_rule_id, account_id.clone());
    let key = SimpleThresholdStorageKey::AccountContext(account_id.clone(), ctx_rule_id);
    let threshold_opt: Option<u32> = e.storage().persistent().get(&key);
    cvlr_assume!(threshold_opt.is_some());
    get_threshold(&e, ctx_rule_id, &account_id);
    cvlr_assert!(true);
}

#[rule]
// if storage is setup can_enforce does not panic
// status: verified
// link: https://prover.certora.com/output/40748/77b92956f46c47e980883b164ee2d81c/?anonymousKey=9035f9923a813c045c3556dc873cf1cf402e49db
pub fn can_enforce_non_panic(e: Env, context: soroban_sdk::auth::Context) {
    let authenticated_signers: Vec<Signer> = nondet_signers_vec();
    let ctx_rule: ContextRule = ContextRule::nondet();
    let account_id = nondet_address();
    storage_setup_threshold(e.clone(), ctx_rule.id, account_id.clone());
    can_enforce(&e, &context, &authenticated_signers, &ctx_rule, &account_id);
    cvlr_assert!(true);
}

#[rule]
// if storage_is_setup, can_enforce returns true, and account_id is auth, then enforce does not panic
// status: verified
// link: https://prover.certora.com/output/40748/77b92956f46c47e980883b164ee2d81c/?anonymousKey=9035f9923a813c045c3556dc873cf1cf402e49db
pub fn enforce_non_panic(
    e: Env,
    context: soroban_sdk::auth::Context,
    unused_context: soroban_sdk::auth::Context,
) {
    let authenticated_signers: Vec<Signer> = nondet_signers_vec();
    let ctx_rule: ContextRule = ContextRule::nondet();
    let account_id = nondet_address();
    storage_setup_threshold(e.clone(), ctx_rule.id, account_id.clone());
    let can_enforce_result = can_enforce(
        &e,
        &unused_context,
        &authenticated_signers,
        &ctx_rule,
        &account_id,
    );
    cvlr_assume!(can_enforce_result && is_auth(account_id.clone()));
    enforce(&e, &context, &authenticated_signers, &ctx_rule, &account_id);
    cvlr_assert!(true);
}

#[rule]
// if storage is setup, account_id is auth, setting a valid threshold, then install does not panic
// status: verified
// link: https://prover.certora.com/output/40748/77b92956f46c47e980883b164ee2d81c/?anonymousKey=9035f9923a813c045c3556dc873cf1cf402e49db
pub fn install_non_panic(e: Env) {
    let params: SimpleThresholdAccountParams = SimpleThresholdAccountParams::nondet();
    let ctx_rule: ContextRule = ContextRule::nondet();
    let account_id = nondet_address();
    storage_setup_threshold(e.clone(), ctx_rule.id, account_id.clone());
    cvlr_assume!(is_auth(account_id.clone()));
    let threshold = params.threshold;
    cvlr_assume!(threshold != 0 && threshold <= ctx_rule.signers.len());
    install(&e, &params, &ctx_rule, &account_id);
    cvlr_assert!(true);
}

#[rule]
// if storage is setup, account_id is auth, then uninstall does not panic
// status: verified
// link: https://prover.certora.com/output/40748/77b92956f46c47e980883b164ee2d81c/?anonymousKey=9035f9923a813c045c3556dc873cf1cf402e49db
pub fn uninstall_non_panic(e: Env) {
    let ctx_rule: ContextRule = ContextRule::nondet();
    let account_id = nondet_address();
    storage_setup_threshold(e.clone(), ctx_rule.id, account_id.clone());
    cvlr_assume!(is_auth(account_id.clone()));
    uninstall(&e, &ctx_rule, &account_id);
    cvlr_assert!(true);
}
