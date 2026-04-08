use cvlr::{clog, cvlr_assert, cvlr_assume, cvlr_satisfy, nondet::*};
use cvlr_soroban::nondet_address;
use cvlr_soroban_derive::rule;
use soroban_sdk::{Address, Env};

use crate::non_fungible::{
    consecutive::storage::NFTConsecutiveStorageKey, extensions::consecutive::Consecutive,
    overrides::ContractOverrides, sequential, specs::helper::is_approved_for_token,
};

// property: P-XX. Consecutive-Integrity.
// description: Consecutive NFT functions change state as expected.
// status: verified

// ################## INTEGRITY RULES ##################

#[rule]
// transfer decreases balance from correctly
// status: verified
pub fn nft_consecutive_transfer_decreases_balance_from(e: Env) {
    let to = nondet_address();
    let from = nondet_address();
    let token_id = u32::nondet();

    let balance_from_pre = Consecutive::balance(&e, &from);
    Consecutive::transfer(&e, &from, &to, token_id);
    let balance_from_post = Consecutive::balance(&e, &from);

    if to != from {
        cvlr_assert!(balance_from_post == balance_from_pre - 1);
    } else {
        cvlr_assert!(balance_from_post == balance_from_pre);
    }
}

#[rule]
// transfer increases balance to correctly
// status: verified
pub fn nft_consecutive_transfer_increases_balance_to(e: Env) {
    let to = nondet_address();
    let from = nondet_address();
    let token_id = u32::nondet();

    let balance_to_pre = Consecutive::balance(&e, &to);
    Consecutive::transfer(&e, &from, &to, token_id);
    let balance_to_post = Consecutive::balance(&e, &to);

    if to != from {
        cvlr_assert!(balance_to_post == balance_to_pre + 1);
    } else {
        cvlr_assert!(balance_to_post == balance_to_pre);
    }
}

#[rule]
// transfer sets owner in storage
// status: verified
pub fn nft_consecutive_transfer_sets_owner_simplified(e: Env) {
    let to = nondet_address();
    let from = nondet_address();
    let token_id = u32::nondet();

    Consecutive::transfer(&e, &from, &to, token_id);
    let owner_post: Option<Address> =
        e.storage().persistent().get(&NFTConsecutiveStorageKey::Owner(token_id));
    cvlr_assert!(owner_post.is_some() && owner_post.unwrap() == to);
}

#[rule]
// updates balance of from correctly
// status: verified
pub fn nft_consecutive_transfer_from_decreases_balance_from(e: Env) {
    let spender = nondet_address();
    let from = nondet_address();
    let to = nondet_address();
    let token_id = u32::nondet();

    let balance_from_pre = Consecutive::balance(&e, &from);

    Consecutive::transfer_from(&e, &spender, &from, &to, token_id);

    let balance_from_post = Consecutive::balance(&e, &from);

    if to != from {
        cvlr_assert!(balance_from_post == balance_from_pre - 1);
    } else {
        cvlr_assert!(balance_from_post == balance_from_pre);
    }
}

#[rule]
// transfer_from increases balance of to correctly
// status: verified
pub fn nft_consecutive_transfer_from_increases_balance_to(e: Env) {
    let spender = nondet_address();
    let from = nondet_address();
    let to = nondet_address();
    let token_id = u32::nondet();

    let balance_to_pre = Consecutive::balance(&e, &to);

    Consecutive::transfer_from(&e, &spender, &from, &to, token_id);

    let balance_to_post = Consecutive::balance(&e, &to);

    if to != from {
        cvlr_assert!(balance_to_post == balance_to_pre + 1);
    } else {
        cvlr_assert!(balance_to_post == balance_to_pre);
    }
}

#[rule]
// transfer_from removes approval
// status: verified
pub fn nft_consecutive_transfer_from_removes_approval(e: Env) {
    let spender = nondet_address();
    let from = nondet_address();
    let to = nondet_address();
    let token_id = u32::nondet();

    let balance_to_pre = Consecutive::balance(&e, &to);

    Consecutive::transfer_from(&e, &spender, &from, &to, token_id);

    let approval_post = Consecutive::get_approved(&e, token_id);
    cvlr_assert!(approval_post.is_none());
}

#[rule]
// after transfer_from the token owner is set to to address in storage
// status: verified
pub fn nft_consecutive_transfer_from_sets_owner_simplified(e: Env) {
    let spender = nondet_address();
    let from = nondet_address();
    let to = nondet_address();
    let token_id = u32::nondet();

    Consecutive::transfer_from(&e, &spender, &from, &to, token_id);

    let owner_post: Option<Address> =
        e.storage().persistent().get(&NFTConsecutiveStorageKey::Owner(token_id));
    cvlr_assert!(owner_post.is_some() && owner_post.unwrap() == to);
}

#[rule]
// after approve the token owner is approved
// status: verified
pub fn nft_consecutive_approve_sets_approval(e: Env) {
    let approver = nondet_address();
    clog!(cvlr_soroban::Addr(&approver));
    let approved = nondet_address();
    clog!(cvlr_soroban::Addr(&approved));
    let token_id = u32::nondet();
    clog!(token_id);
    let owner_pre = Consecutive::owner_of(&e, token_id);
    clog!(cvlr_soroban::Addr(&owner_pre));
    let live_until_ledger = u32::nondet();
    clog!(live_until_ledger);
    cvlr_assume!(live_until_ledger > 0);
    Consecutive::approve(&e, &approver, &approved, token_id, live_until_ledger);
    let is_approved_for_token_post = is_approved_for_token(&e, &approver, &approved, token_id);
    clog!(is_approved_for_token_post);
    cvlr_assert!(is_approved_for_token_post);
}

// there is no approve_for_all function

#[rule]
// batch_mint changes balance correctly
// the owner_of the first_token id is "to"
// status: verified
pub fn nft_batch_mint_increases_balance(e: Env) {
    let to = nondet_address();
    clog!(cvlr_soroban::Addr(&to));
    let amount = u32::nondet();
    clog!(amount);
    let balance_pre = Consecutive::balance(&e, &to);
    clog!(balance_pre);
    let current_token_id = sequential::next_token_id(&e);
    clog!(current_token_id);
    Consecutive::batch_mint(&e, &to, amount);
    let balance_post = Consecutive::balance(&e, &to);
    clog!(balance_post);
    cvlr_assert!(balance_post == balance_pre + amount);
}
