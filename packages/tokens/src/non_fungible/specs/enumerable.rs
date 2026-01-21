// property: P-XX. Enumerable-Integrity.
// description: Enumerable NFT functions change state as expected.
// status: verified

use cvlr::{clog, cvlr_assert, cvlr_assume, cvlr_satisfy, nondet::*};
use cvlr_soroban::nondet_address;
use cvlr_soroban_derive::rule;
use soroban_sdk::{Address, Env};

use crate::non_fungible::{
    enumerable::Enumerable,
    extensions::enumerable::storage::{NFTEnumerableStorageKey, OwnerTokensKey},
    overrides::ContractOverrides,
    Base, OWNER_EXTEND_AMOUNT, OWNER_TTL_THRESHOLD, TOKEN_EXTEND_AMOUNT, TOKEN_TTL_THRESHOLD,
};
use crate::non_fungible::utils::sequential;
use crate::non_fungible::specs::helper::is_owned;

// P-XX. Enumerable-Integrity.
// description: Enumerable NFT functions change state as expected.
// status: verified

// helpers

/// Returns the `token_id` owned by `owner` at a given `index` in the
/// owner's local list, or `None` if not found. This is a non-panicking
/// version of [`Enumerable::get_owner_token_id`].
pub fn try_get_owner_token_id(e: &Env, owner: &Address, index: u32) -> Option<u32> {
    let key = NFTEnumerableStorageKey::OwnerTokens(OwnerTokensKey { owner: owner.clone(), index });
    let Some(token_id) = e.storage().persistent().get::<_, u32>(&key) else {
        return None;
    };
    e.storage().persistent().extend_ttl(&key, OWNER_TTL_THRESHOLD, OWNER_EXTEND_AMOUNT);
    Some(token_id)
}

pub fn try_get_owner_token_index(e: &Env, owner: &Address, token_id: u32) -> Option<u32> {
    let key = NFTEnumerableStorageKey::OwnerTokensIndex(token_id);
    let Some(index) = e.storage().persistent().get::<_, u32>(&key) else {
        return None;
    };
    e.storage().persistent().extend_ttl(&key, TOKEN_TTL_THRESHOLD, TOKEN_EXTEND_AMOUNT);
    Some(index)
}

/// Returns the `token_id` at a given `index` in the global token list,
/// or `None` if not found. This is a non-panicking version of
/// [`Enumerable::get_token_id`].
pub fn try_get_token_id(e: &Env, index: u32) -> Option<u32> {
    let key = NFTEnumerableStorageKey::GlobalTokens(index);
    let Some(token_id) = e.storage().persistent().get::<_, u32>(&key) else {
        return None;
    };
    e.storage().persistent().extend_ttl(&key, TOKEN_TTL_THRESHOLD, TOKEN_EXTEND_AMOUNT);

    Some(token_id)
}

pub fn try_get_token_index(e: &Env, token_id: u32) -> Option<u32> {
    let key = NFTEnumerableStorageKey::GlobalTokensIndex(token_id);
    let Some(index) = e.storage().persistent().get::<_, u32>(&key) else {
        return None;
    };
    e.storage().persistent().extend_ttl(&key, TOKEN_TTL_THRESHOLD, TOKEN_EXTEND_AMOUNT);
    Some(index)
}

// ################## SEQUENTIAL MINT INTEGRITY ##################

#[rule]
// sequential_mint sets the token owner to the recipient
// status: verified
// link: https://prover.certora.com/output/5771024/6f94087858a2422485aea1ac6889b1ea/?anonymousKey=559bba3da2b23ad6bc1195787f629be5d79a7ce0
pub fn enumerable_sequential_mint_sets_owner(e: Env) {
    let to = nondet_address();
    clog!(cvlr_soroban::Addr(&to));
    let next_token_id = sequential::next_token_id(&e);
    clog!(next_token_id);
    Enumerable::sequential_mint(&e, &to);
    let owner_post = Enumerable::owner_of(&e, next_token_id);
    clog!(cvlr_soroban::Addr(&owner_post));
    cvlr_assert!(owner_post == to);
}

#[rule]
// sequential_mint increases the recipient's balance by 1
// status: verified
// link: https://prover.certora.com/output/5771024/6f94087858a2422485aea1ac6889b1ea/?anonymousKey=559bba3da2b23ad6bc1195787f629be5d79a7ce0
pub fn enumerable_sequential_mint_increases_balance(e: Env) {
    let to = nondet_address();
    clog!(cvlr_soroban::Addr(&to));
    let next_token_id = sequential::next_token_id(&e);
    clog!(next_token_id);
    let balance_pre = Enumerable::balance(&e, &to);
    clog!(balance_pre);
    Enumerable::sequential_mint(&e, &to);
    let balance_post = Enumerable::balance(&e, &to);
    clog!(balance_post);
    cvlr_assert!(balance_post == balance_pre + 1);
}

#[rule]
// sequential_mint increases total supply by 1
// status: verified
// link: https://prover.certora.com/output/5771024/6f94087858a2422485aea1ac6889b1ea/?anonymousKey=559bba3da2b23ad6bc1195787f629be5d79a7ce0
pub fn enumerable_sequential_mint_increases_total_supply(e: Env) {
    let to = nondet_address();
    clog!(cvlr_soroban::Addr(&to));
    let next_token_id = sequential::next_token_id(&e);
    clog!(next_token_id);
    let total_supply_pre = Enumerable::total_supply(&e);
    clog!(total_supply_pre);
    Enumerable::sequential_mint(&e, &to);
    let total_supply_post = Enumerable::total_supply(&e);
    clog!(total_supply_post);
    cvlr_assert!(total_supply_post == total_supply_pre + 1);
}

#[rule]
// sequential_mint sets the token index
// status: verified
// link: https://prover.certora.com/output/5771024/6f94087858a2422485aea1ac6889b1ea/?anonymousKey=559bba3da2b23ad6bc1195787f629be5d79a7ce0
pub fn enumerable_sequential_mint_sets_token_index(e: Env) {
    let to = nondet_address();
    clog!(cvlr_soroban::Addr(&to));
    let next_token_id = sequential::next_token_id(&e);
    clog!(next_token_id);
    Enumerable::sequential_mint(&e, &to);
    let index_post = try_get_token_index(&e, next_token_id);
    clog!(index_post);
    cvlr_assert!(index_post.is_some());
}

#[rule]
// sequential_mint sets token index to total_supply - 1
// status: verified
// link: https://prover.certora.com/output/5771024/6f94087858a2422485aea1ac6889b1ea/?anonymousKey=559bba3da2b23ad6bc1195787f629be5d79a7ce0
pub fn enumerable_sequential_mint_token_index_is_total_supply_minus_one(e: Env) {
    let to = nondet_address();
    clog!(cvlr_soroban::Addr(&to));
    let next_token_id = sequential::next_token_id(&e);
    clog!(next_token_id);
    Enumerable::sequential_mint(&e, &to);
    let index_post = try_get_token_index(&e, next_token_id);
    clog!(index_post);
    let total_supply_post = Enumerable::total_supply(&e);
    cvlr_assert!(index_post == Some(total_supply_post - 1));
}

#[rule]
// sequential_mint sets the owner token index
// status: verified
// link: https://prover.certora.com/output/5771024/6f94087858a2422485aea1ac6889b1ea/?anonymousKey=559bba3da2b23ad6bc1195787f629be5d79a7ce0
pub fn enumerable_sequential_mint_sets_owner_token_index(e: Env) {
    let to = nondet_address();
    clog!(cvlr_soroban::Addr(&to));
    let next_token_id = sequential::next_token_id(&e);
    clog!(next_token_id);
    Enumerable::sequential_mint(&e, &to);
    let index_post = try_get_owner_token_index(&e, &to, next_token_id);
    clog!(index_post);
    cvlr_assert!(index_post.is_some());
}

#[rule]
// sequential_mint sets owner token index to balance - 1
// status: verified
// link: https://prover.certora.com/output/5771024/6f94087858a2422485aea1ac6889b1ea/?anonymousKey=559bba3da2b23ad6bc1195787f629be5d79a7ce0
pub fn enumerable_sequential_mint_owner_token_index_is_balance_minus_one(e: Env) {
    let to = nondet_address();
    clog!(cvlr_soroban::Addr(&to));
    let next_token_id = sequential::next_token_id(&e);
    clog!(next_token_id);
    Enumerable::sequential_mint(&e, &to);
    let index_post = try_get_owner_token_index(&e, &to, next_token_id);
    clog!(index_post);
    let balance_post = Enumerable::balance(&e, &to);
    clog!(balance_post);
    cvlr_assert!(index_post == Some(balance_post - 1));
}

// ################## NON-SEQUENTIAL MINT INTEGRITY ##################

#[rule]
// non_sequential_mint sets the token owner to the recipient
// status: verified
// link: https://prover.certora.com/output/5771024/6f94087858a2422485aea1ac6889b1ea/?anonymousKey=559bba3da2b23ad6bc1195787f629be5d79a7ce0
pub fn enumerable_non_sequential_mint_sets_owner(e: Env) {
    let to = nondet_address();
    clog!(cvlr_soroban::Addr(&to));
    let token_id = u32::nondet();
    clog!(token_id);
    Enumerable::non_sequential_mint(&e, &to, token_id);
    let owner_post = Enumerable::owner_of(&e, token_id);
    clog!(cvlr_soroban::Addr(&owner_post));
    cvlr_assert!(owner_post == to);
}

#[rule]
// non_sequential_mint increases the recipient's balance by 1
// status: verified
// link: https://prover.certora.com/output/5771024/6f94087858a2422485aea1ac6889b1ea/?anonymousKey=559bba3da2b23ad6bc1195787f629be5d79a7ce0
pub fn enumerable_non_sequential_mint_increases_balance(e: Env) {
    let to = nondet_address();
    clog!(cvlr_soroban::Addr(&to));
    let token_id = u32::nondet();
    clog!(token_id);
    let balance_pre = Enumerable::balance(&e, &to);
    clog!(balance_pre);
    Enumerable::non_sequential_mint(&e, &to, token_id);
    let balance_post = Enumerable::balance(&e, &to);
    clog!(balance_post);
    cvlr_assert!(balance_post == balance_pre + 1);
}

#[rule]
// non_sequential_mint increases total supply by 1
// status: verified
// link: https://prover.certora.com/output/5771024/6f94087858a2422485aea1ac6889b1ea/?anonymousKey=559bba3da2b23ad6bc1195787f629be5d79a7ce0
pub fn enumerable_non_sequential_mint_increases_total_supply(e: Env) {
    let to = nondet_address();
    clog!(cvlr_soroban::Addr(&to));
    let token_id = u32::nondet();
    clog!(token_id);
    let total_supply_pre = Enumerable::total_supply(&e);
    clog!(total_supply_pre);
    Enumerable::non_sequential_mint(&e, &to, token_id);
    let total_supply_post = Enumerable::total_supply(&e);
    clog!(total_supply_post);
    cvlr_assert!(total_supply_post == total_supply_pre + 1);
}

#[rule]
// non_sequential_mint sets the token index
// status: verified
// link: https://prover.certora.com/output/5771024/6f94087858a2422485aea1ac6889b1ea/?anonymousKey=559bba3da2b23ad6bc1195787f629be5d79a7ce0
pub fn enumerable_non_sequential_mint_sets_token_index(e: Env) {
    let to = nondet_address();
    clog!(cvlr_soroban::Addr(&to));
    let token_id = u32::nondet();
    clog!(token_id);
    Enumerable::non_sequential_mint(&e, &to, token_id);
    let index_post = try_get_token_index(&e, token_id);
    clog!(index_post);
    cvlr_assert!(index_post.is_some());
}

#[rule]
// non_sequential_mint sets token index to total_supply - 1
// status: verified
// link: https://prover.certora.com/output/5771024/6f94087858a2422485aea1ac6889b1ea/?anonymousKey=559bba3da2b23ad6bc1195787f629be5d79a7ce0
pub fn enumerable_non_sequential_mint_token_index_is_total_supply_minus_one(e: Env) {
    let to = nondet_address();
    clog!(cvlr_soroban::Addr(&to));
    let token_id = u32::nondet();
    clog!(token_id);
    Enumerable::non_sequential_mint(&e, &to, token_id);
    let index_post = try_get_token_index(&e, token_id);
    clog!(index_post);
    let total_supply_post = Enumerable::total_supply(&e);
    clog!(total_supply_post);
    cvlr_assert!(index_post == Some(total_supply_post - 1));
}

#[rule]
// non_sequential_mint sets the owner token index
// status: verified
// link: https://prover.certora.com/output/5771024/6f94087858a2422485aea1ac6889b1ea/?anonymousKey=559bba3da2b23ad6bc1195787f629be5d79a7ce0  
pub fn enumerable_non_sequential_mint_sets_owner_token_index(e: Env) {
    let to = nondet_address();
    clog!(cvlr_soroban::Addr(&to));
    let token_id = u32::nondet();
    clog!(token_id);
    Enumerable::non_sequential_mint(&e, &to, token_id);
    let index_post = try_get_owner_token_index(&e, &to, token_id);
    clog!(index_post);
    cvlr_assert!(index_post.is_some());
}

#[rule]
// non_sequential_mint sets owner token index to balance - 1
// status: verified
// link: https://prover.certora.com/output/5771024/6f94087858a2422485aea1ac6889b1ea/?anonymousKey=559bba3da2b23ad6bc1195787f629be5d79a7ce0
pub fn enumerable_non_sequential_mint_owner_token_index_is_balance_minus_one(e: Env) {
    let to = nondet_address();
    clog!(cvlr_soroban::Addr(&to));
    let token_id = u32::nondet();
    clog!(token_id);
    Enumerable::non_sequential_mint(&e, &to, token_id);
    let index_post = try_get_owner_token_index(&e, &to, token_id);
    clog!(index_post);
    let balance_post = Enumerable::balance(&e, &to);
    clog!(balance_post);
    cvlr_assert!(index_post == Some(balance_post - 1));
}

// ################## BURN INTEGRITY ##################

#[rule]
// burn decreases total supply by 1
// status: verified
// link: https://prover.certora.com/output/5777712/823069677713496385827512929451d2/?anonymousKey=559bba3da2b23ad6bc1195787f629be5d79a7ce0
pub fn enumerable_burn_decreases_total_supply(e: Env) {
    let from = nondet_address();
    clog!(cvlr_soroban::Addr(&from));
    let token_id = u32::nondet();
    clog!(token_id);
    let total_supply_pre = Enumerable::total_supply(&e);
    clog!(total_supply_pre);
    Enumerable::burn(&e, &from, token_id);
    let total_supply_post = Enumerable::total_supply(&e);
    clog!(total_supply_post);
    cvlr_assert!(total_supply_post == total_supply_pre - 1);
}

#[rule]
// burn decreases the owner's balance by 1
// status: verified
// link: https://prover.certora.com/output/5777712/823069677713496385827512929451d2/?anonymousKey=559bba3da2b23ad6bc1195787f629be5d79a7ce0
pub fn enumerable_burn_decreases_balance(e: Env) {
    let from = nondet_address();
    clog!(cvlr_soroban::Addr(&from));
    let token_id = u32::nondet();
    clog!(token_id);
    let balance_pre = Enumerable::balance(&e, &from);
    clog!(balance_pre);
    Enumerable::burn(&e, &from, token_id);
    let balance_post = Enumerable::balance(&e, &from);
    clog!(balance_post);
    cvlr_assert!(balance_post == balance_pre - 1);
}

// ################## BURN FROM INTEGRITY ##################

#[rule]
// burn_from decreases total supply by 1
// status: verified
// link: https://prover.certora.com/output/5777712/823069677713496385827512929451d2/?anonymousKey=559bba3da2b23ad6bc1195787f629be5d79a7ce0
pub fn enumerable_burn_from_decreases_total_supply(e: Env) {
    let from = nondet_address();
    clog!(cvlr_soroban::Addr(&from));
    let token_id = u32::nondet();
    clog!(token_id);
    let total_supply_pre = Enumerable::total_supply(&e);
    clog!(total_supply_pre);
    Enumerable::burn_from(&e, &from, &from, token_id);
    let total_supply_post = Enumerable::total_supply(&e);
    clog!(total_supply_post);
    cvlr_assert!(total_supply_post == total_supply_pre - 1);
}

#[rule]
// burn_from decreases the owner's balance by 1
// status: verified
// link: https://prover.certora.com/output/5777712/823069677713496385827512929451d2/?anonymousKey=559bba3da2b23ad6bc1195787f629be5d79a7ce0
pub fn enumerable_burn_from_decreases_balance(e: Env) {
    let from = nondet_address();
    clog!(cvlr_soroban::Addr(&from));
    let token_id = u32::nondet();
    clog!(token_id);
    let balance_pre = Enumerable::balance(&e, &from);
    clog!(balance_pre);
    Enumerable::burn_from(&e, &from, &from, token_id);
    let balance_post = Enumerable::balance(&e, &from);
    clog!(balance_post);
    cvlr_assert!(balance_post == balance_pre - 1);
}

#[rule]
// burn_from removes the token approval
// status: verified
// link: https://prover.certora.com/output/5777712/823069677713496385827512929451d2/?anonymousKey=559bba3da2b23ad6bc1195787f629be5d79a7ce0
pub fn enumerable_burn_from_removes_approval(e: Env) {
    let from = nondet_address();
    clog!(cvlr_soroban::Addr(&from));
    let token_id = u32::nondet();
    clog!(token_id);
    Enumerable::burn_from(&e, &from, &from, token_id);
    let approval_post = Enumerable::get_approved(&e, token_id);
    cvlr_assert!(approval_post.is_none());
}

// ################## TRANSFER INTEGRITY ##################

#[rule]
// transfer sets the token owner to the recipient
// status: verified
// link: https://prover.certora.com/output/5771024/4fc0cb8020974b59ac266841ac96370b/?anonymousKey=0077faa3f3bc2f2485168b034b2499f02bbc1f08
pub fn enumerable_transfer_sets_owner(e: Env) {
    let to = nondet_address();
    clog!(cvlr_soroban::Addr(&to));
    let from = nondet_address();
    clog!(cvlr_soroban::Addr(&from));
    let token_id = u32::nondet();
    clog!(token_id);
    Enumerable::transfer(&e, &from, &to, token_id);
    let owner_post = Enumerable::owner_of(&e, token_id);
    clog!(cvlr_soroban::Addr(&owner_post));
    cvlr_assert!(owner_post == to);
}

#[rule]
// transfer preserves total supply
// status: verified
// link: https://prover.certora.com/output/5771024/4fc0cb8020974b59ac266841ac96370b/?anonymousKey=0077faa3f3bc2f2485168b034b2499f02bbc1f08
pub fn enumerable_transfer_preserves_total_supply(e: Env) {
    let to = nondet_address();
    clog!(cvlr_soroban::Addr(&to));
    let from = nondet_address();
    clog!(cvlr_soroban::Addr(&from));
    let token_id = u32::nondet();
    clog!(token_id);
    let total_supply_pre = Enumerable::total_supply(&e);
    clog!(total_supply_pre);
    Enumerable::transfer(&e, &from, &to, token_id);
    let total_supply_post = Enumerable::total_supply(&e);
    clog!(total_supply_post);
    cvlr_assert!(total_supply_post == total_supply_pre);
}

#[rule]
// transfer preserves the token's global index
// status: verified
// link: https://prover.certora.com/output/5771024/4fc0cb8020974b59ac266841ac96370b/?anonymousKey=0077faa3f3bc2f2485168b034b2499f02bbc1f08
pub fn enumerable_transfer_preserves_token_index(e: Env) {
    let to = nondet_address();
    clog!(cvlr_soroban::Addr(&to));
    let from = nondet_address();
    clog!(cvlr_soroban::Addr(&from));
    let token_id = u32::nondet();
    clog!(token_id);
    let index_pre = try_get_token_index(&e, token_id);
    clog!(index_pre);
    Enumerable::transfer(&e, &from, &to, token_id);
    let index_post = try_get_token_index(&e, token_id);
    clog!(index_post);
    cvlr_assert!(index_post == index_pre);
}

// ################## TRANSFER FROM INTEGRITY ##################

#[rule]
// transfer_from sets the token owner to the recipient
// status: verified
// link: https://prover.certora.com/output/5771024/4fc0cb8020974b59ac266841ac96370b/?anonymousKey=0077faa3f3bc2f2485168b034b2499f02bbc1f08
pub fn enumerable_transfer_from_sets_owner(e: Env) {
    let spender = nondet_address();
    clog!(cvlr_soroban::Addr(&spender));
    let to = nondet_address();
    clog!(cvlr_soroban::Addr(&to));
    let from = nondet_address();
    clog!(cvlr_soroban::Addr(&from));
    let token_id = u32::nondet();
    clog!(token_id);
    Enumerable::transfer_from(&e, &spender, &from, &to, token_id);
    let owner_post = Enumerable::owner_of(&e, token_id);
    clog!(cvlr_soroban::Addr(&owner_post));
    cvlr_assert!(owner_post == to);
}

#[rule]
// transfer_from preserves total supply
// status: verified
// link: https://prover.certora.com/output/5771024/4fc0cb8020974b59ac266841ac96370b/?anonymousKey=0077faa3f3bc2f2485168b034b2499f02bbc1f08
pub fn enumerable_transfer_from_preserves_total_supply(e: Env) {
    let spender = nondet_address();
    clog!(cvlr_soroban::Addr(&spender));
    let to = nondet_address();
    clog!(cvlr_soroban::Addr(&to));
    let from = nondet_address();
    clog!(cvlr_soroban::Addr(&from));
    let token_id = u32::nondet();
    clog!(token_id);
    let total_supply_pre = Enumerable::total_supply(&e);
    clog!(total_supply_pre);
    Enumerable::transfer_from(&e, &spender, &from, &to, token_id);
    let total_supply_post = Enumerable::total_supply(&e);
    clog!(total_supply_post);
    cvlr_assert!(total_supply_post == total_supply_pre);
}

#[rule]
// transfer_from preserves the token's global index
// status: verified
// link: https://prover.certora.com/output/5771024/4fc0cb8020974b59ac266841ac96370b/?anonymousKey=0077faa3f3bc2f2485168b034b2499f02bbc1f08
pub fn enumerable_transfer_from_preserves_token_index(e: Env) {
    let spender = nondet_address();
    clog!(cvlr_soroban::Addr(&spender));
    let to = nondet_address();
    clog!(cvlr_soroban::Addr(&to));
    let from = nondet_address();
    clog!(cvlr_soroban::Addr(&from));
    let token_id = u32::nondet();
    clog!(token_id);
    let index_pre = try_get_token_index(&e, token_id);
    clog!(index_pre);
    Enumerable::transfer_from(&e, &spender, &from, &to, token_id);
    let index_post = try_get_token_index(&e, token_id);
    clog!(index_post);
    cvlr_assert!(index_post == index_pre);
}

#[rule]
// transfer_from removes the token approval
// status: verified
// link: https://prover.certora.com/output/5771024/4fc0cb8020974b59ac266841ac96370b/?anonymousKey=0077faa3f3bc2f2485168b034b2499f02bbc1f08      
pub fn enumerable_transfer_from_removes_approval(e: Env) {
    let spender = nondet_address();
    clog!(cvlr_soroban::Addr(&spender));
    let to = nondet_address();
    clog!(cvlr_soroban::Addr(&to));
    let from = nondet_address();
    clog!(cvlr_soroban::Addr(&from));
    let token_id = u32::nondet();
    clog!(token_id);
    Enumerable::transfer_from(&e, &spender, &from, &to, token_id);
    let approval_post = Enumerable::get_approved(&e, token_id);
    cvlr_assert!(approval_post.is_none());
}
