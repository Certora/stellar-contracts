use cvlr::{clog, cvlr_assert, cvlr_assume, cvlr_satisfy, nondet::Nondet};
use cvlr_soroban::nondet_address;
use cvlr_soroban_derive::rule;
use soroban_sdk::Env;

use crate::ownable::{
    specs::{helper::get_pending_owner, ownable_contract::OwnableContract},
    *,
};

// property: P-04. Ownable-Invariants.
// description: Invariants: 1. owner != None (except for when renounce_ownership
// is called) and 2. pending_owner != none implies owner != none.
// status: verified

// invariant: owner != None -> holds in all cases except for renounce_ownership

// helpers
pub fn assume_pre_owner_is_set(e: Env) {
    let owner_pre = OwnableContract::get_owner(&e);
    cvlr_assume!(owner_pre.is_some());
}

pub fn assert_post_owner_is_set(e: Env) {
    let owner_post = OwnableContract::get_owner(&e);
    cvlr_assert!(owner_post.is_some());
}

#[rule]
// invariant: owner != None, case: constructor
// status: verified
pub fn after_constructor_owner_is_set(e: Env) {
    let new_owner = nondet_address();
    OwnableContract::ownable_constructor(&e, new_owner);
    assert_post_owner_is_set(e);
}

#[rule]
// invariant: owner != None, case: transfer_ownership
// status: verified
pub fn after_transfer_ownership_pending_owner_is_set(e: Env) {
    assume_pre_owner_is_set(e.clone());
    let new_owner = nondet_address();
    let live_until_ledger = u32::nondet();
    OwnableContract::transfer_ownership(&e, new_owner, live_until_ledger);
    assert_post_owner_is_set(e);
}

#[rule]
// invariant: owner != None, case: accept_ownership
// status: verified
pub fn after_accept_ownership_owner_is_set(e: Env) {
    assume_pre_owner_is_set(e.clone());
    OwnableContract::accept_ownership(&e);
    assert_post_owner_is_set(e);
}

// for the case renounce_ownership it's obviously false - and expected

#[rule]
// invariant: owner != None, case: owner_restricted_function
// status: verified
pub fn after_owner_restricted_function_owner_is_set(e: Env) {
    assume_pre_owner_is_set(e.clone());
    OwnableContract::owner_restricted_function(&e);
    assert_post_owner_is_set(e);
}

// invariant: pending_owner != none implies owner != none

// helpers
pub fn assume_pre_pending_owner_implies_owner(e: &Env) {
    let pending_owner_pre = get_pending_owner(e);
    if let Some(pend_pre) = pending_owner_pre.clone() {
        clog!(cvlr_soroban::Addr(&pend_pre));
    }
    let owner = OwnableContract::get_owner(&e);
    if let Some(owner_internal_pre) = owner.clone() {
        clog!(cvlr_soroban::Addr(&owner_internal_pre));
    }
    if pending_owner_pre.is_some() {
        cvlr_assume!(owner.is_some());
    }
}

pub fn assert_post_pending_owner_implies_owner(e: &Env) {
    let pending_owner_post = get_pending_owner(&e);
    if let Some(pend_post) = pending_owner_post.clone() {
        clog!(cvlr_soroban::Addr(&pend_post));
    }
    let owner = OwnableContract::get_owner(&e);
    if let Some(owner_internal_post) = owner.clone() {
        clog!(cvlr_soroban::Addr(&owner_internal_post));
    }
    if pending_owner_post.is_some() {
        cvlr_assert!(owner.is_some());
    }
}

#[rule]
// invariant: pending_owner != none implies owner != none, case: constructor
// status: verified
pub fn after_constructor_pending_owner_implies_owner(e: Env) {
    let new_owner = nondet_address();
    OwnableContract::ownable_constructor(&e, new_owner);
    assert_post_pending_owner_implies_owner(&e);
}

#[rule]
// invariant: pending_owner != none implies owner != none, case:
// transfer_ownership status: verified
pub fn after_transfer_ownership_pending_owner_implies_owner(e: Env) {
    assume_pre_pending_owner_implies_owner(&e);
    let new_owner = nondet_address();
    let live_until_ledger = u32::nondet();
    OwnableContract::transfer_ownership(&e, new_owner, live_until_ledger);
    assert_post_pending_owner_implies_owner(&e);
}

#[rule]
// invariant: pending_owner != none implies owner != none, case:
// accept_ownership status: verified
pub fn after_accept_ownership_pending_owner_implies_owner(e: Env) {
    assume_pre_pending_owner_implies_owner(&e);
    OwnableContract::accept_ownership(&e);
    assert_post_pending_owner_implies_owner(&e);
}

#[rule]
// invariant: pending_owner != none implies owner != none, case:
// renounce_ownership status: verified
pub fn after_renounce_ownership_pending_owner_implies_owner(e: Env) {
    assume_pre_pending_owner_implies_owner(&e);
    OwnableContract::renounce_ownership(&e);
    assert_post_pending_owner_implies_owner(&e);
}

#[rule]
// invariant: pending_owner != none implies owner != none, case:
// owner_restricted_function status: verified
pub fn after_owner_restricted_function_pending_owner_implies_owner(e: Env) {
    assume_pre_pending_owner_implies_owner(&e);
    OwnableContract::owner_restricted_function(&e);
    assert_post_pending_owner_implies_owner(&e);
}
