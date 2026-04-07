use cvlr::{
    clog, cvlr_assert, cvlr_assume, cvlr_satisfy,
    nondet::{self, Nondet},
};
use cvlr_soroban::nondet_address;
use cvlr_soroban_derive::rule;
use soroban_sdk::{
    auth::{Context, ContractContext},
    symbol_short, Address, Env, IntoVal, Vec,
};

use crate::{
    policies::{
        spending_limit::{
            can_enforce, enforce, get_spending_limit_data, install, set_spending_limit, uninstall,
            SpendingLimitAccountParams, SpendingLimitData, SpendingLimitStorageKey,
        },
        Policy,
    },
    smart_account::{specs::nondet::nondet_signers_vec, ContextRule, Signer},
};

// property: P-XX. SpendingLimit-Invariants.
// description: SpendingLimit invariants are preserved across all operations.
// status: verified

// invariant: spending_limit > 0

// helpers

pub fn assume_pre_spending_limit_gt_zero(e: Env, ctx_rule: ContextRule, account_id: Address) {
    let spending_limit: i128 = get_spending_limit_data(&e, ctx_rule.id, &account_id).spending_limit;
    clog!(spending_limit);
    cvlr_assume!(spending_limit > 0);
}

pub fn assert_post_spending_limit_gt_zero(e: Env, ctx_rule: ContextRule, account_id: Address) {
    let spending_limit: i128 = get_spending_limit_data(&e, ctx_rule.id, &account_id).spending_limit;
    clog!(spending_limit);
    cvlr_assert!(spending_limit > 0);
}

// rules

#[rule]
// invariant: spending_limit > 0, case: install
// status: verified
// link: https://prover.certora.com/output/5771024/a7272a72ed8d4102abbd1df505031f20/?anonymousKey=4cc4b78d1f9987bb1e74458ef1e4616432f98ef0
pub fn sl_after_install_spending_limit_gt_zero(e: Env) {
    let ctx_rule: ContextRule = ContextRule::nondet();
    let account_id: Address = nondet_address();
    install(&e, &SpendingLimitAccountParams::nondet(), &ctx_rule, &account_id);
    assert_post_spending_limit_gt_zero(e.clone(), ctx_rule.clone(), account_id.clone());
}

#[rule]
// invariant: spending_limit > 0, case: uninstall
// status: verified
// link: https://prover.certora.com/output/5771024/0054528c2e574210874926620c30d73d/?anonymousKey=8229c1669e893c81b224482a7639b4349d773160
pub fn sl_after_uninstall_spending_limit_gt_zero(e: Env) {
    let ctx_rule: ContextRule = ContextRule::nondet();
    let account_id: Address = nondet_address();
    assume_pre_spending_limit_gt_zero(e.clone(), ctx_rule.clone(), account_id.clone());
    uninstall(&e, &ctx_rule, &account_id);
    assert_post_spending_limit_gt_zero(e.clone(), ctx_rule.clone(), account_id.clone());
}

#[rule]
// invariant: spending_limit > 0, case: set_spending_limit
// status: verified
// link: https://prover.certora.com/output/5771024/0054528c2e574210874926620c30d73d/?anonymousKey=8229c1669e893c81b224482a7639b4349d773160
pub fn sl_after_set_spending_limit_spending_limit_gt_zero(e: Env) {
    let spending_limit: i128 = i128::nondet();
    let ctx_rule: ContextRule = ContextRule::nondet();
    let account_id: Address = nondet_address();
    assume_pre_spending_limit_gt_zero(e.clone(), ctx_rule.clone(), account_id.clone());
    set_spending_limit(&e, spending_limit, &ctx_rule, &account_id);
    assert_post_spending_limit_gt_zero(e.clone(), ctx_rule.clone(), account_id.clone());
}

#[rule]
// invariant: spending_limit > 0, case: can_enforce
// status: verified
// link: https://prover.certora.com/output/5771024/0054528c2e574210874926620c30d73d/?anonymousKey=8229c1669e893c81b224482a7639b4349d773160
pub fn sl_after_can_enforce_spending_limit_gt_zero(e: Env, context: Context) {
    let ctx_rule: ContextRule = ContextRule::nondet();
    let account_id: Address = nondet_address();
    assume_pre_spending_limit_gt_zero(e.clone(), ctx_rule.clone(), account_id.clone());
    let auth_signers: Vec<Signer> = nondet_signers_vec();
    can_enforce(&e, &context, &auth_signers, &ctx_rule, &account_id);
    assert_post_spending_limit_gt_zero(e.clone(), ctx_rule.clone(), account_id.clone());
}

#[rule]
// invariant: spending_limit > 0, case: enforce
// status: verified
// link: https://prover.certora.com/output/5771024/0054528c2e574210874926620c30d73d/?anonymousKey=8229c1669e893c81b224482a7639b4349d773160
pub fn sl_after_enforce_spending_limit_gt_zero(e: Env, context: Context) {
    let ctx_rule: ContextRule = ContextRule::nondet();
    let account_id: Address = nondet_address();
    assume_pre_spending_limit_gt_zero(e.clone(), ctx_rule.clone(), account_id.clone());
    let auth_signers: Vec<Signer> = nondet_signers_vec();
    enforce(&e, &context, &auth_signers, &ctx_rule, &account_id);
    assert_post_spending_limit_gt_zero(e.clone(), ctx_rule.clone(), account_id.clone());
}
