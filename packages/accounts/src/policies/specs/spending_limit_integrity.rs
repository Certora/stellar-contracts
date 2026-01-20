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
        spending_limit::{can_enforce, enforce, get_spending_limit_data, install, set_spending_limit, uninstall, SpendingLimitAccountParams, SpendingLimitData, SpendingLimitStorageKey},
        Policy,
    },
    smart_account::{specs::nondet::nondet_signers_vec, ContextRule, Signer},
};

// note we verify the rules in this file with:
// "loop_iter": 1 or 2
// "optimistic_loop": true
// meaning we consider only runs where the loops are iterated at most 1/2 times.

#[rule]
// after set_spending_limit the spending_limit is set to the input
// status: verified
pub fn sl_set_spending_limit_integrity(e: Env) {
    let spending_limit: i128 = i128::nondet();
    let ctx_rule: ContextRule = ContextRule::nondet();
    let account_id = nondet_address();
    set_spending_limit(
        &e,
        spending_limit,
        &ctx_rule.clone(),
        &account_id.clone(),
    );
    let spending_limit_data_post =
        get_spending_limit_data(&e, ctx_rule.id, &account_id);
    let spending_limit_post = spending_limit_data_post.spending_limit;
    cvlr_assert!(spending_limit_post == spending_limit);
}

#[rule]
// can_enforce returns false if there is no spending limit data associated with the smart account and context
// status: verified 
pub fn sl_can_enforce_returns_false_if_no_spending_limit_data(e: Env, context: Context) {
    let auth_signers: Vec<Signer> = nondet_signers_vec();
    let ctx_rule: ContextRule = ContextRule::nondet();
    let account_id = nondet_address();
    let key = SpendingLimitStorageKey::AccountContext(account_id.clone(), ctx_rule.id);
    cvlr_assume!(e.storage().persistent().get::<_, SpendingLimitData>(&key).is_none());
    let result = can_enforce(&e, &context.clone(), &auth_signers.clone(), &ctx_rule.clone(), &account_id.clone());
    cvlr_assert!(!result);
}

// can_enforce returns false for a context that is not a contract call
// status: verified
pub fn sl_can_enforce_returns_false_if_not_contract_call(e: Env, context: Context) {
    let auth_signers: Vec<Signer> = nondet_signers_vec();
    let ctx_rule: ContextRule = ContextRule::nondet();
    let account_id = nondet_address();
    let context_is_contract_call = matches!(context, Context::Contract(_));
    cvlr_assume!(!context_is_contract_call);
    let result = can_enforce(&e, &context.clone(), &auth_signers.clone(), &ctx_rule.clone(), &account_id.clone());
    cvlr_assert!(!result);
}

#[rule]
// can_enforce returns false for a transaction that is not a transfer
// status: verified
pub fn sl_can_enforce_returns_false_if_not_transfer(e: Env, context: Context) {
    let auth_signers: Vec<Signer> = nondet_signers_vec();
    let ctx_rule: ContextRule = ContextRule::nondet();
    let account_id = nondet_address();
    let context_is_transfer = matches!(context.clone(), Context::Contract(ContractContext { fn_name, .. }) if fn_name == symbol_short!("transfer"));
    cvlr_assume!(!context_is_transfer);
    let result = can_enforce(&e, &context.clone(), &auth_signers.clone(), &ctx_rule.clone(), &account_id.clone());
    cvlr_assert!(!result);
}

#[rule]
// example where can_enforce returns true
// status: timeout
pub fn sl_can_enforce_returns_true_if_amount_leq_spending_limit(e: Env, context: Context) {
    let auth_signers: Vec<Signer> = nondet_signers_vec();
    cvlr_assume!(!auth_signers.is_empty());
    let ctx_rule: ContextRule = ContextRule::nondet();
    let from = nondet_address();
    clog!(cvlr_soroban::Addr(&from));
    let to = nondet_address();
    clog!(cvlr_soroban::Addr(&to));
    let amount = i128::nondet();
    clog!(amount);
    let mut args = Vec::new(&e);
    args.push_back(from.into_val(&e));
    args.push_back(to.into_val(&e));
    args.push_back(amount.into_val(&e));
    let contract_context = Context::Contract(ContractContext {
        fn_name: symbol_short!("transfer"),
        args,
        contract: nondet_address(),
    });
    let account_id = nondet_address();
    clog!(cvlr_soroban::Addr(&account_id));
    let spending_limit_data =
        get_spending_limit_data(&e, ctx_rule.id, &account_id.clone());
    let spending_limit = spending_limit_data.spending_limit;
    clog!(spending_limit);
    let total_spent = spending_limit_data.cached_total_spent;
    clog!(total_spent);
    cvlr_assume!(total_spent == 0);
    cvlr_assume!(amount <= spending_limit);
    let result = can_enforce(&e, &context, &auth_signers.clone(), &ctx_rule, &account_id);
    cvlr_assert!(result);
}


#[rule]
// enforce increases cached_total_spent
// status: violation - seems to be when total_spent < 0 pre (unreachable presumably)
pub fn sl_enforce_integrity(e: Env, context: Context) {
    let auth_signers: Vec<Signer> = nondet_signers_vec();
    let ctx_rule: ContextRule = ContextRule::nondet();
    let account_id = nondet_address();
    let spending_limit_data_pre = get_spending_limit_data(&e, ctx_rule.id, &account_id.clone());
    let total_spent_pre = spending_limit_data_pre.cached_total_spent;
    clog!(total_spent_pre);
    enforce(&e, &context.clone(), &auth_signers.clone(), &ctx_rule.clone(), &account_id.clone());
    let spending_limit_data_post = get_spending_limit_data(&e, ctx_rule.id, &account_id.clone());
    let total_spent_post = spending_limit_data_post.cached_total_spent;
    cvlr_assert!(total_spent_post >= total_spent_pre);
}


#[rule]
// after install the spending_limit_data is set to the input
// status: verified
pub fn sl_install_integrity(e: Env) {
    let params: SpendingLimitAccountParams = SpendingLimitAccountParams::nondet();
    let params_spending_limit = params.spending_limit;
    let params_period_ledgers = params.period_ledgers;
    let ctx_rule: ContextRule = ContextRule::nondet();
    let account_id = nondet_address();
    install(&e, &params.clone(), &ctx_rule.clone(), &account_id.clone());
    let spending_limit_data_post =
        get_spending_limit_data(&e, ctx_rule.id, &account_id.clone());
    let spending_limit_data_post_spending_limit = spending_limit_data_post.spending_limit;
    let spending_limit_data_post_period_ledgers = spending_limit_data_post.period_ledgers;
    cvlr_assert!(spending_limit_data_post_spending_limit == params_spending_limit);
    cvlr_assert!(spending_limit_data_post_period_ledgers == params_period_ledgers);
}

#[rule]
// after uninstall the spending_limit_data is removed
// status: verified
pub fn sl_uninstall_integrity(e: Env) {
    let ctx_rule: ContextRule = ContextRule::nondet();
    let account_id = nondet_address();
    uninstall(&e, &ctx_rule.clone(), &account_id.clone());
    let key: SpendingLimitStorageKey =
        SpendingLimitStorageKey::AccountContext(account_id.clone(), ctx_rule.id);
    let account_ctx_opt: Option<SpendingLimitData> = e.storage().persistent().get(&key);
    cvlr_assert!(account_ctx_opt.is_none());
}
