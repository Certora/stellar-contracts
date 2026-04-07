use cvlr::{clog, cvlr_assert, cvlr_assume, cvlr_satisfy, nondet::*};
use cvlr_soroban::{nondet_address, nondet_map, nondet_string};
use cvlr_soroban_derive::rule;
use soroban_sdk::{map, panic_with_error, vec, Address, Env, String, Val, Vec};

use crate::smart_account::{
    specs::{
        helper::{
            get_count, get_ids_of_rule_type, get_meta_of_id, get_next_id, get_policies_of_id,
            get_signers_of_id,
        },
        nondet::{nondet_policy_map, nondet_signers_vec},
    },
    storage::{
        add_context_rule, add_policy, add_signer, get_context_rule, get_persistent_entry,
        get_valid_context_rules, remove_context_rule, remove_policy, remove_signer,
        update_context_rule_name, update_context_rule_valid_until, ContextRule,
        SmartAccountStorageKey,
    },
    ContextRuleType, Meta, Signer, SmartAccount, SmartAccountError,
};

// property: P-XX. Smart-Account-Integrity.
// description: Smart account storage functions change state as expected.
// status: verified

#[rule]
// update_context_rule_name changes the name correctly
// status: verified
pub fn update_context_rule_name_integrity(e: Env) {
    let id = nondet();
    let name = nondet_string();
    let ctx_rule_pre = get_context_rule(&e, id);
    update_context_rule_name(&e, id, &name);
    let ctx_rule_post = get_context_rule(&e, id);
    let name_post = ctx_rule_post.name;
    cvlr_assert!(name_post == name);
}

#[rule]
// update_context_rule_valid_until changes the valid_until correctly
// status: verified
pub fn update_context_rule_valid_until_integrity(e: Env) {
    let id: u32 = nondet();
    let valid_until = Option::<u32>::nondet();
    let ctx_rule_post = update_context_rule_valid_until(&e, id, valid_until);
    let valid_until_post = ctx_rule_post.valid_until;
    cvlr_assert!(valid_until_post == valid_until);
}

#[rule]
// remove_context_rule decrements the rule count correctly
// status: verified
pub fn remove_context_rule_integrity_1(e: Env) {
    let id: u32 = nondet();
    clog!(id);
    let ctx_rule_pre = get_context_rule(&e, id);
    let rule_count_pre = get_count(e.clone());
    remove_context_rule(&e, id);
    let rule_count_post = get_count(e.clone());
    cvlr_assert!(rule_count_post == rule_count_pre - 1);
}

#[rule]
// add_signer adds the signer to the context rule
// status: verified
pub fn add_signer_integrity(e: Env) {
    let id: u32 = nondet();
    let signer = Signer::nondet();
    let meta = Meta::nondet();

    // with this storage setup the rule verifies
    let signers: Vec<Signer> = Vec::new(&e);
    // perhaps it would also verify if we push one signer e.g
    e.storage().persistent().set(&SmartAccountStorageKey::Signers(id), &signers);

    add_signer(&e, id, &signer);

    let ctx_rule_post = get_context_rule(&e, id);
    cvlr_assert!(ctx_rule_post.signers.contains(&signer));
}

#[rule]
// remove_signer removes the signer from the context rule
// status: verified
pub fn remove_signer_integrity(e: Env) {
    let id: u32 = nondet();
    let signer = Signer::nondet();

    let meta = Meta::nondet();
    e.storage().persistent().set(&SmartAccountStorageKey::Meta(id), &meta);

    // add a single signer because `remove_signer` assumes no duplicates and
    // `add_signer` does not allow duplicates.
    let mut signers = Vec::new(&e);
    signers.push_back(signer.clone());
    e.storage().persistent().set(&SmartAccountStorageKey::Signers(id), &signers);
    // raz: doesn't make sense to me

    remove_signer(&e, id, &signer);

    let ctx_rule_post = get_context_rule(&e, id);
    cvlr_assert!(!ctx_rule_post.signers.contains(&signer));
}
