use cvlr::{cvlr_assert, cvlr_assume, cvlr_satisfy, nondet::Nondet};
use cvlr_soroban::{is_auth, nondet_address};
use cvlr_soroban_derive::rule;
use soroban_sdk::{Address, Env};

use crate::ownable::{
    specs::{helper::get_pending_owner, ownable_contract::OwnableContract},
    OwnableStorageKey, *,
};

// property: P-03. Ownable-Non-Panics.
// description: Ownable functions do not under appropriate assumptions.
// status: verified

// These rules require the prover arg "prover_args": ["-trapAsAssert true"] to
// consider also panicking paths.

#[rule]
// if: storage is setup, owner exists, owner auth, pending owner is some,
// pending owner auth, live until ledger is appropriate then transfer_ownership
// does not panic status: verified
pub fn transfer_ownership_non_panic(e: Env) {
    let address1 = nondet_address();
    e.storage().temporary().set(&OwnableStorageKey::PendingOwner, &address1);

    let address2 = nondet_address();
    e.storage().instance().set(&OwnableStorageKey::Owner, &address2);

    let new_owner = nondet_address().clone();
    let live_until_ledger = u32::nondet();

    let owner = OwnableContract::get_owner(&e);
    cvlr_assume!(owner.is_some());
    if let Some(owner_internal) = owner.clone() {
        cvlr_assume!(is_auth(owner_internal));
    }

    let pending_owner = get_pending_owner(&e);
    if let Some(pending_owner_internal) = pending_owner.clone() {
        cvlr_assume!(pending_owner_internal == new_owner);
    }

    if live_until_ledger == 0 {
        cvlr_assume!(pending_owner.is_some());
    } else {
        cvlr_assume!(live_until_ledger >= e.ledger().sequence());
        cvlr_assume!(live_until_ledger <= e.ledger().max_live_until_ledger());
    }

    OwnableContract::transfer_ownership(&e, new_owner, live_until_ledger);
    cvlr_assert!(true);
}

#[rule]
// if: storage is setup, pending owner is some, pending owner auth then
// accept_ownership does not panic status: verified
pub fn accept_ownership_non_panic(e: Env) {
    let address1 = nondet_address();
    e.storage().temporary().set(&OwnableStorageKey::PendingOwner, &address1);

    let address2 = nondet_address();
    e.storage().instance().set(&OwnableStorageKey::Owner, &address2);

    let pending_owner = get_pending_owner(&e);
    cvlr_assume!(pending_owner.is_some() && is_auth(pending_owner.unwrap()));
    OwnableContract::accept_ownership(&e);
    cvlr_assert!(true);
}

#[rule]
// if: storage is setup, pending owner is none then renounce_ownership does not
// panic status: verified
pub fn renounce_ownership_non_panic(e: Env) {
    // // setup storage: needed for now.
    // // WIP: will have this macro for setting storage up automatically.
    // // require_storage_tag(OwnableStorageKey::PendingOwner.into_val(&e), 77);

    e.storage().temporary().set(&OwnableStorageKey::PendingOwner, &nondet_address());
    e.storage().temporary().remove(&OwnableStorageKey::PendingOwner);

    e.storage().instance().set(&OwnableStorageKey::Owner, &nondet_address());
    let owner = OwnableContract::get_owner(&e).unwrap();

    cvlr_assume!(is_auth(owner));

    OwnableContract::renounce_ownership(&e);
    cvlr_assert!(true);
}

#[rule]
// if: storage is setup, owner exists, owner auth then owner_restricted_function
// does not panic status: verified
pub fn owner_restricted_function_non_panic(e: Env) {
    let address1 = nondet_address();
    e.storage().temporary().set(&OwnableStorageKey::PendingOwner, &address1);

    let address2 = nondet_address();
    e.storage().instance().set(&OwnableStorageKey::Owner, &address2);

    let owner = OwnableContract::get_owner(&e);
    cvlr_assume!(owner.is_some());
    if let Some(owner_internal) = owner.clone() {
        cvlr_assume!(is_auth(owner_internal));
    }
    OwnableContract::owner_restricted_function(&e);
    cvlr_assert!(true);
}
