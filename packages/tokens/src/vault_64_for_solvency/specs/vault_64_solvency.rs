use cvlr::{clog, cvlr_assert, cvlr_assume, cvlr_satisfy, nondet::*};
use cvlr_soroban::nondet_address;
use cvlr_soroban_derive::rule;
use soroban_sdk::{Address, Env};
use stellar_contract_utils::math::fixed_point::Rounding;

use crate::vault_64_for_solvency::specs::helpers::{effective_total_assets, effective_total_supply, safe_assumptions};
use crate::vault_64_for_solvency::{
    specs::{asset_token::AssetToken, vault::BasicVault},
    FungibleVault, Vault,
};
use crate::vault_64_for_solvency::fungible_64::FungibleToken;

// invariant: effective total assets >= effective total supply

// helpers

pub fn assume_pre_solvency(e: &Env) {
    let total_assets = effective_total_assets(e);
    clog!(total_assets);
    let total_supply = effective_total_supply(e);
    clog!(total_supply);
    cvlr_assume!(total_assets >= total_supply);
}

pub fn assert_post_solvency(e: &Env) {
    let total_assets = effective_total_assets(e);
    clog!(total_assets);
    let total_supply = effective_total_supply(e);
    clog!(total_supply);
    cvlr_assert!(total_assets >= total_supply);
}

#[rule]
// status: verified
// link: https://prover.certora.com/output/33158/ac2d01eb8af048459ab9796f18882b91
pub fn after_transfer_solvency_64(e: Env) {
    safe_assumptions(&e);
    assume_pre_solvency(&e);
    let from = nondet_address();
    clog!(cvlr_soroban::Addr(&from));
    let to = nondet_address();
    clog!(cvlr_soroban::Addr(&to));
    let amount: i64 = nondet();
    clog!(amount);
    BasicVault::transfer(&e, from, to, amount);
    assert_post_solvency(&e);
}

#[rule]
// status: verified
// link: https://prover.certora.com/output/33158/ac2d01eb8af048459ab9796f18882b91
pub fn after_transfer_from_solvency_64(e: Env) {
    safe_assumptions(&e);
    assume_pre_solvency(&e);
    let spender = nondet_address();
    clog!(cvlr_soroban::Addr(&spender));
    let from = nondet_address();
    clog!(cvlr_soroban::Addr(&from));
    let to = nondet_address();
    clog!(cvlr_soroban::Addr(&to));
    let amount: i64 = nondet();
    clog!(amount);
    BasicVault::transfer_from(&e, spender, from, to, amount);
    assert_post_solvency(&e);
}

#[rule]
// status: verified
// link: https://prover.certora.com/output/33158/b6dc966eac1c4f74b6d23d81eab5bebc
pub fn after_approve_solvency_64(e: Env) {
    safe_assumptions(&e);
    assume_pre_solvency(&e);
    let owner = nondet_address();
    clog!(cvlr_soroban::Addr(&owner));
    let spender = nondet_address();
    clog!(cvlr_soroban::Addr(&spender));
    let amount: i64 = nondet();
    clog!(amount);
    let live_until_ledger: u32 = nondet();
    clog!(live_until_ledger);
    BasicVault::approve(&e, owner, spender, amount, live_until_ledger);
    assert_post_solvency(&e);
}

#[rule]
// status: timeout
pub fn after_deposit_solvency_64(e: Env) {
    safe_assumptions(&e);
    assume_pre_solvency(&e);
    let assets: i64 = nondet();
    clog!(assets);
    let receiver: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&receiver));
    let from: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&from));
    let operator: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&operator));
    BasicVault::deposit(&e, assets, receiver, from, operator);
    assert_post_solvency(&e);
}

#[rule]
// status: timeout
pub fn after_mint_solvency_64(e: Env) {
    safe_assumptions(&e);
    assume_pre_solvency(&e);
    let shares: i64 = nondet();
    clog!(shares);
    let receiver: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&receiver));
    let from: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&from));
    let operator: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&operator));
    BasicVault::mint(&e, shares, receiver, from, operator);
    assert_post_solvency(&e);
}

#[rule]
// status: timeout
pub fn after_withdraw_solvency_64(e: Env) {
    safe_assumptions(&e);
    assume_pre_solvency(&e);
    let assets: i64 = nondet();
    clog!(assets);
    let receiver: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&receiver));
    let owner: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&owner));
    let operator: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&operator));
    BasicVault::withdraw(&e, assets, receiver, owner, operator);
    assert_post_solvency(&e);
}

#[rule]
// status: timeout
pub fn after_redeem_solvency_64(e: Env) {
    safe_assumptions(&e);
    assume_pre_solvency(&e);
    let shares: i64 = nondet();
    clog!(shares);
    let receiver: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&receiver));
    let owner: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&owner));
    let operator: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&operator));
    BasicVault::redeem(&e, shares, receiver, owner, operator);
    assert_post_solvency(&e);
}

// solvency is obviously not maintained when changing the decimal offset or
// underlying asset.

// we can check also for the operations on the underlying token, so long as the
// current contract doesn't send tokens.

#[rule]
// status: verified
// note: there was the same issue with checked_add so i changed our impl of
// effective_total_assets and effective_total_supply.
// link: https://prover.certora.com/output/33158/939a8868fa674812ad81834a79e36a4f
pub fn after_token_transfer_solvency_64(e: Env) {
    safe_assumptions(&e);
    assume_pre_solvency(&e);
    let from: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&from));
    let to: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&to));
    let amount: i64 = nondet();
    clog!(amount);
    let current_contract_address = e.current_contract_address();
    clog!(cvlr_soroban::Addr(&current_contract_address));
    cvlr_assume!(from != current_contract_address); // contract doesn't send its tokens
    AssetToken::transfer(&e, from, to, amount);
    assert_post_solvency(&e);
}

#[rule]
// status: verified
// link: https://prover.certora.com/output/33158/a8d89a668bd6476da4a2832f711fddfb
pub fn after_token_transfer_from_solvency_64(e: Env) {
    safe_assumptions(&e);
    assume_pre_solvency(&e);
    let spender: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&spender));
    let from: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&from));
    let to: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&to));
    let amount: i64 = nondet();
    clog!(amount);
    let current_contract_address = e.current_contract_address();
    clog!(cvlr_soroban::Addr(&current_contract_address));
    cvlr_assume!(from != current_contract_address); // contract doesn't send its tokens
    AssetToken::transfer_from(&e, spender, from, to, amount);
    assert_post_solvency(&e);
}

#[rule]
// status: verified
// link: https://prover.certora.com/output/33158/24bbe3d44b6340808fbcc3fd56dee2a3
pub fn after_token_approve_solvency_64(e: Env) {
    safe_assumptions(&e);
    assume_pre_solvency(&e);
    let owner: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&owner));
    let spender: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&spender));
    let amount: i64 = nondet();
    clog!(amount);
    let live_until_ledger: u32 = nondet();
    clog!(live_until_ledger);
    // contract can technically approve, that doesn't break solvency (yet)
    AssetToken::approve(&e, owner, spender, amount, live_until_ledger);
    assert_post_solvency(&e);
}

#[rule]
// status: verified
// link: https://prover.certora.com/output/33158/139a21d87b25490ebd5a74ac6b0e03fa
pub fn convert_to_shares_and_solvency_64(e: Env) {
    safe_assumptions(&e);
    assume_pre_solvency(&e);
    let effective_total_assets = effective_total_assets(&e);
    clog!(effective_total_assets);
    let effective_total_supply = effective_total_supply(&e);
    clog!(effective_total_supply);
    let assets: i64 = nondet();
    clog!(assets);
    let shares = BasicVault::convert_to_shares(&e, assets);
    clog!(shares);
    let expected_effective_total_assets = effective_total_assets + assets;
    clog!(expected_effective_total_assets);
    let expected_effective_total_supply = effective_total_supply + shares;
    clog!(expected_effective_total_supply);
    cvlr_assert!(expected_effective_total_assets >= expected_effective_total_supply);
}

#[rule]
// status: 
// link: https://prover.certora.com/output/33158/b51f9936923241c9adad4b2b79e2a50d
pub fn convert_to_assets_and_solvency_64(e: Env) {
    safe_assumptions(&e);
    assume_pre_solvency(&e);
    let effective_total_assets = effective_total_assets(&e);
    clog!(effective_total_assets);
    let effective_total_supply = effective_total_supply(&e);
    clog!(effective_total_supply);
    let shares: i64 = nondet();
    clog!(shares);
    let assets = BasicVault::convert_to_assets(&e, shares);
    clog!(assets);
    let expected_effective_total_assets = effective_total_assets + assets;
    clog!(expected_effective_total_assets);
    let expected_effective_total_supply = effective_total_supply + shares;
    clog!(expected_effective_total_supply);
    cvlr_assert!(expected_effective_total_assets >= expected_effective_total_supply);
}
