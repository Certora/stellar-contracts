use cvlr::{
    clog, cvlr_assert, cvlr_assume, cvlr_satisfy,
    nondet::{nondet, Nondet},
};
use cvlr_soroban::{is_auth, nondet_address, nondet_symbol};
use cvlr_soroban_derive::rule;
use soroban_sdk::{Address, Env, Symbol};

use crate::access_control::{
    specs::{access_control_contract::AccessControlContract, helper::get_pending_admin},
    storage::{AccessControlStorageKey, RoleAccountKey},
    AccessControl,
};

// property: P-07. Access-Control-Non-Panics.
// description: Access Control functions do not panic under appropriate
// assumptions. status: verified

// These rules require the prover arg "prover_args": ["-trapAsAssert true"] to
// consider also panicking paths.

// storage is setup

// im a bit unsure about storage is setup in cases where there are options,
// is the case of None ignored the way we do this?

pub fn storage_setup_admin(e: Env) {
    let admin = nondet_address();
    e.storage().instance().set(&AccessControlStorageKey::Admin, &admin);
}

pub fn storage_setup_pending_admin(e: Env) {
    let pending_admin = nondet_address();
    e.storage().temporary().set(&AccessControlStorageKey::PendingAdmin, &pending_admin);
}

pub fn storage_setup_pending_admin_none(e: Env) {
    let pending_admin: Option<Address> = None::<Address>;
    e.storage().temporary().set(&AccessControlStorageKey::PendingAdmin, &pending_admin.clone());
}

pub fn storage_setup_role_admin(e: Env, role: Symbol) {
    let role_admin_key: AccessControlStorageKey = AccessControlStorageKey::RoleAdmin(role.clone());
    let symbol = nondet_symbol();
    e.storage().persistent().set(&role_admin_key, &symbol);
}

pub fn storage_setup_role_counts(e: Env, role: Symbol) {
    let role_accounts_count_key: AccessControlStorageKey =
        AccessControlStorageKey::RoleAccountsCount(role.clone());
    let nondet_count: u32 = nondet();
    e.storage().persistent().set(&role_accounts_count_key, &nondet_count);
}

pub fn storage_setup_account_has_role(e: Env, account: Address, role: Symbol) {
    let has_role_key = AccessControlStorageKey::HasRole(account.clone(), role.clone());
    let nondet_index_account: u32 = nondet();
    e.storage().persistent().set(&has_role_key, &nondet_index_account);
}

pub fn storage_setup_caller_has_role_admin(e: Env, caller: Address, role: Symbol) {
    let role_admin = AccessControlContract::get_role_admin(&e, role.clone());
    if let Some(role_admin_internal) = role_admin {
        let caller_has_role_admin_key =
            AccessControlStorageKey::HasRole(caller.clone(), role_admin_internal.clone());
        let nondet_index: u32 = nondet();
        e.storage().persistent().set(&caller_has_role_admin_key, &nondet_index);
    }
}

pub fn storage_setup_last_account(e: Env, role: Symbol) {
    let count = AccessControlContract::get_role_member_count(&e, role.clone());
    let last_index = count - 1;
    let last_key = AccessControlStorageKey::RoleAccounts(RoleAccountKey {
        role: role.clone(),
        index: last_index,
    });
    let last_account = nondet_address();
    e.storage().persistent().set(&last_key, &last_account);
}

// package functions

#[rule]
// if: storage is setup, caller auth and caller is admin or has admin role then
// grant_role does not panic status: verified
// link: https://prover.certora.com/output/40748/86c9538348fc4f7aaec74a0007f9f336/?anonymousKey=93b13006a8d89ab76818946db2f4eded4567a5d3
pub fn grant_role_non_panic(e: Env) {
    let caller = nondet_address();
    let account = nondet_address();
    let role = nondet_symbol();

    storage_setup_admin(e.clone());
    storage_setup_role_admin(e.clone(), role.clone());
    storage_setup_account_has_role(e.clone(), account.clone(), role.clone());
    storage_setup_caller_has_role_admin(e.clone(), caller.clone(), role.clone());

    cvlr_assume!(is_auth(caller.clone()));
    let admin = AccessControlContract::get_admin(&e);
    let mut caller_equals_admin = false;
    if let Some(admin_internal) = admin {
        caller_equals_admin = caller.clone() == admin_internal;
    }
    let mut caller_has_role_admin = false;
    let role_admin = AccessControlContract::get_role_admin(&e, role.clone());
    if let Some(role_admin_internal) = role_admin {
        caller_has_role_admin =
            AccessControlContract::has_role(&e, caller.clone(), role_admin_internal).is_some();
    }
    cvlr_assume!(caller_equals_admin || caller_has_role_admin);
    AccessControlContract::grant_role(&e, account, role, caller);
    cvlr_assert!(true);
}


#[rule]
// if storage is setup, admin exists, admin auth, pending owner can only be the
// same as new_admin, and live until ledger is appropriate then
// transfer_admin_role does not panic status: verified
// link: https://prover.certora.com/output/40748/86c9538348fc4f7aaec74a0007f9f336/?anonymousKey=93b13006a8d89ab76818946db2f4eded4567a5d3
pub fn transfer_admin_role_non_panic(e: Env) {
    let new_admin = nondet_address().clone();
    let live_until_ledger = u32::nondet();

    storage_setup_pending_admin(e.clone());
    storage_setup_admin(e.clone());

    let admin = AccessControlContract::get_admin(&e);
    cvlr_assume!(admin.is_some());
    if let Some(admin_internal) = admin.clone() {
        cvlr_assume!(is_auth(admin_internal));
    }

    let pending_admin = get_pending_admin(&e);
    if let Some(pending_admin_internal) = pending_admin.clone() {
        cvlr_assume!(pending_admin_internal == new_admin);
    }

    if live_until_ledger == 0 {
        cvlr_assume!(pending_admin.is_some());
    } else {
        cvlr_assume!(live_until_ledger >= e.ledger().sequence());
        cvlr_assume!(live_until_ledger <= e.ledger().max_live_until_ledger());
    }

    AccessControlContract::transfer_admin_role(&e, new_admin, live_until_ledger);
    cvlr_assert!(true);
}

#[rule]
// if: storage is setup, pending admin exists and pending admin auth then
// accept_admin_transfer does not panic status: verified
// link: https://prover.certora.com/output/40748/86c9538348fc4f7aaec74a0007f9f336/?anonymousKey=93b13006a8d89ab76818946db2f4eded4567a5d3
pub fn accept_admin_transfer_non_panic(e: Env) {
    storage_setup_pending_admin(e.clone());
    storage_setup_admin(e.clone());

    let pending_admin = get_pending_admin(&e);
    cvlr_assume!(pending_admin.is_some());
    if let Some(pending_admin_internal) = pending_admin.clone() {
        cvlr_assume!(is_auth(pending_admin_internal));
    }
    AccessControlContract::accept_admin_transfer(&e);
    cvlr_assert!(true);
}

#[rule]
// if: storage is setup, admin exists and admin auth then set_role_admin does
// not panic status: verified
// link: https://prover.certora.com/output/40748/86c9538348fc4f7aaec74a0007f9f336/?anonymousKey=93b13006a8d89ab76818946db2f4eded4567a5d3
pub fn set_role_admin_non_panic(e: Env) {
    let role = nondet_symbol();
    let admin_role = nondet_symbol();
    storage_setup_admin(e.clone());
    storage_setup_role_admin(e.clone(), role.clone());
    let admin = AccessControlContract::get_admin(&e);
    cvlr_assume!(admin.is_some());
    if let Some(admin_internal) = admin.clone() {
        cvlr_assume!(is_auth(admin_internal));
    }
    AccessControlContract::set_role_admin(&e, role.clone(), admin_role.clone());
    cvlr_assert!(true);
}