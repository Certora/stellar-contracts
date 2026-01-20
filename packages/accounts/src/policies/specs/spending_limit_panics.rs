use cvlr::{
    clog, cvlr_assert, cvlr_assume, cvlr_satisfy,
    nondet::{self, Nondet},
};
use cvlr_soroban::{is_auth, nondet_address};
use cvlr_soroban_derive::rule;
use soroban_sdk::{
    auth::{Context, ContractContext},
    symbol_short, Address, Env, IntoVal, Vec,
};

use crate::{
    policies::{
        spending_limit::{can_enforce, enforce, get_spending_limit_data, install, set_spending_limit, uninstall, SpendingLimitAccountParams, SpendingLimitData, SpendingLimitStorageKey},
        Policy,
    },
    smart_account::{specs::nondet::nondet_signers_vec, ContextRule, Signer},
};

#[rule]
// set_spending_limit panics if spending limit is not positive
// status: verified 
pub fn sl_set_spending_limit_panics_if_invalid_limit(e: Env) {
    let spending_limit: i128 = i128::nondet();
    let ctx_rule: ContextRule = ContextRule::nondet();
    let account_id = nondet_address();
    cvlr_assume!(spending_limit <= 0);
    set_spending_limit(&e, spending_limit, &ctx_rule.clone(), &account_id.clone());
    cvlr_assert!(false);
}

#[rule]
// set_spending_limit panics if unauth by smart_account
// status: verified
pub fn sl_set_spending_limit_panics_if_unauth(e: Env) {
    let spending_limit: i128 = i128::nondet();
    let ctx_rule: ContextRule = ContextRule::nondet();
    let account_id = nondet_address();
    cvlr_assume!(!is_auth(account_id.clone()));
    set_spending_limit(&e, spending_limit, &ctx_rule.clone(), &account_id.clone());
    cvlr_assert!(false);
}

#[rule]
// set_spending_limit panics if not installed
// status: verified
pub fn sl_set_spending_limit_panics_if_not_installed(e: Env) {
    let spending_limit: i128 = i128::nondet();
    let ctx_rule: ContextRule = ContextRule::nondet();
    let account_id = nondet_address();
    let key = SpendingLimitStorageKey::AccountContext(account_id.clone(), ctx_rule.id);
    let params_opt: Option<SpendingLimitAccountParams> = e.storage().persistent().get(&key);
    cvlr_assume!(params_opt.is_none());
    set_spending_limit(&e, spending_limit, &ctx_rule.clone(), &account_id.clone());
    cvlr_assert!(false);
}

#[rule]
// install panics if spending limit is not positive
// status: verified
pub fn sl_install_panics_if_invalid_limit(e: Env) {
    let params: SpendingLimitAccountParams = SpendingLimitAccountParams::nondet();
    let ctx_rule: ContextRule = ContextRule::nondet();
    let account_id = nondet_address();
    cvlr_assume!(params.spending_limit <= 0);
    install(&e, &params, &ctx_rule.clone(), &account_id.clone());
    cvlr_assert!(false);
}

#[rule]
// install panics if unauth by smart_account
// status: verified
pub fn sl_install_panics_if_unauth(e: Env) {
    let params: SpendingLimitAccountParams = SpendingLimitAccountParams::nondet();
    let ctx_rule: ContextRule = ContextRule::nondet();
    let account_id = nondet_address();
    cvlr_assume!(!is_auth(account_id.clone()));
    install(&e, &params, &ctx_rule.clone(), &account_id.clone());
    cvlr_assert!(false);
}

#[rule]
// install panics if period_ledgers is zero
// status: verified
pub fn sl_install_panics_if_period_ledgers_is_zero(e: Env) {
    let params: SpendingLimitAccountParams = SpendingLimitAccountParams::nondet();
    let ctx_rule: ContextRule = ContextRule::nondet();
    let account_id = nondet_address();
    cvlr_assume!(params.period_ledgers == 0);
    install(&e, &params, &ctx_rule.clone(), &account_id.clone());
    cvlr_assert!(false);
}

#[rule]
// uninstall panics if unauth by smart_account
// status: verified
pub fn sl_uninstall_panics_if_unauth(e: Env) {
    let ctx_rule: ContextRule = ContextRule::nondet();
    let account_id = nondet_address();
    cvlr_assume!(!is_auth(account_id.clone()));
    uninstall(&e, &ctx_rule.clone(), &account_id.clone());
    cvlr_assert!(false);
}

#[rule]
// enforce panics if can_enforce returns false
// status: spurious violation
// https://prover.certora.com/output/5771024/661d103d71134955bd0224b55b4c1e15/?anonymousKey=7ca8cc8b5990790d83828aeaa6cffc561f37e5a7
// explanation: in can_enforce spending_limit_data is none but in enforce it is not.
pub fn sl_enforce_panics_if_can_enforce_returns_false(e: Env, context: Context) {
    let authenticated_signers: Vec<Signer> = nondet_signers_vec();
    let ctx_rule: ContextRule = ContextRule::nondet();
    let account_id = nondet_address();
    let can_enforce_result = can_enforce(&e, &context.clone(), &authenticated_signers.clone(), &ctx_rule.clone(), &account_id.clone());
    cvlr_assume!(!can_enforce_result);
    enforce(&e, &context, &authenticated_signers, &ctx_rule.clone(), &account_id.clone());
    cvlr_assert!(false);
}