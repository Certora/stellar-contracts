use cvlr::{clog, cvlr_assert, cvlr_assume, cvlr_satisfy, nondet::*};
use cvlr_soroban::nondet_address;
use cvlr_soroban_derive::rule;
use soroban_sdk::{Address, Env};
use stellar_contract_utils::math::fixed_point::Rounding;

use crate::vault_64::{
    fungible_64::FungibleToken,
    specs::{asset_token::AssetToken, vault::BasicVault, vault_64_solvency::assume_pre_solvency},
    FungibleVault, Vault,
};

// property: P-XX. Vault-Invariants.
// description: Vault invariants: 1. total_supply >= 0 and 2. total_assets >= 0.
// status: verified

pub fn safe_assumptions(e: &Env) {
    assume_pre_total_supply_geq_zero(e);
    assume_pre_total_assets_geq_zero(e);
}

// helper assumption - total_supply >= balance

pub fn assume_pre_total_supply_geq_balance(e: &Env, account: &Address) {
    let total_supply = BasicVault::total_supply(e);
    clog!(total_supply);
    let balance = BasicVault::balance(e, account.clone());
    clog!(balance);
    cvlr_assume!(total_supply >= balance);
}

// total_supply >= 0
// helpers
pub fn assume_pre_total_supply_geq_zero(e: &Env) {
    let total_supply = BasicVault::total_supply(e);
    clog!(total_supply);
    cvlr_assume!(total_supply >= 0);
}

pub fn assert_post_total_supply_geq_zero(e: &Env) {
    let total_supply = BasicVault::total_supply(e);
    clog!(total_supply);
    cvlr_assert!(total_supply >= 0);
}

#[rule]
// invariant: total_supply >= 0, case: transfer
// status: verified
// link: https://prover.certora.com/output/5771024/5836f2b6cde24450a77131f33ce5a77b/?anonymousKey=d73db7c427056cffec889b0e36ad6d405a9384bf
pub fn after_transfer_total_supply_geq_zero(e: Env) {
    assume_pre_total_supply_geq_zero(&e);
    let from = nondet_address();
    clog!(cvlr_soroban::Addr(&from));
    let to = nondet_address();
    clog!(cvlr_soroban::Addr(&to));
    let amount: i64 = nondet();
    clog!(amount);
    BasicVault::transfer(&e, from, to, amount);
    assert_post_total_supply_geq_zero(&e);
}

#[rule]
// invariant: total_supply >= 0, case: transfer_from
// status: verified
// link: https://prover.certora.com/output/5771024/5836f2b6cde24450a77131f33ce5a77b/?anonymousKey=d73db7c427056cffec889b0e36ad6d405a9384bf
pub fn after_transfer_from_total_supply_geq_zero(e: Env) {
    assume_pre_total_supply_geq_zero(&e);
    let spender = nondet_address();
    clog!(cvlr_soroban::Addr(&spender));
    let from = nondet_address();
    clog!(cvlr_soroban::Addr(&from));
    let to = nondet_address();
    clog!(cvlr_soroban::Addr(&to));
    let amount: i64 = nondet();
    clog!(amount);
    BasicVault::transfer_from(&e, spender, from, to, amount);
    assert_post_total_supply_geq_zero(&e);
}

#[rule]
// invariant: total_supply >= 0, case: approve
// status: verified
// link: https://prover.certora.com/output/5771024/5836f2b6cde24450a77131f33ce5a77b/?anonymousKey=d73db7c427056cffec889b0e36ad6d405a9384bf
pub fn after_approve_total_supply_geq_zero(e: Env) {
    assume_pre_total_supply_geq_zero(&e);
    let owner = nondet_address();
    clog!(cvlr_soroban::Addr(&owner));
    let spender = nondet_address();
    clog!(cvlr_soroban::Addr(&spender));
    let amount: i64 = nondet();
    clog!(amount);
    let live_until_ledger: u32 = nondet();
    clog!(live_until_ledger);
    BasicVault::approve(&e, owner, spender, amount, live_until_ledger);
    assert_post_total_supply_geq_zero(&e);
}

#[rule]
// invariant: total_supply >= 0, case: deposit
// status: verified
// link: https://prover.certora.com/output/5771024/5836f2b6cde24450a77131f33ce5a77b/?anonymousKey=d73db7c427056cffec889b0e36ad6d405a9384bf
pub fn after_deposit_total_supply_geq_zero(e: Env) {
    assume_pre_total_supply_geq_zero(&e);
    let assets: i64 = nondet();
    clog!(assets);
    let receiver: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&receiver));
    let from: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&from));
    let operator: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&operator));
    BasicVault::deposit(&e, assets, receiver, from, operator);
    assert_post_total_supply_geq_zero(&e);
}

#[rule]
// invariant: total_supply >= 0, case: mint
// status: verified
// link: https://prover.certora.com/output/5771024/5836f2b6cde24450a77131f33ce5a77b/?anonymousKey=d73db7c427056cffec889b0e36ad6d405a9384bf
pub fn after_mint_total_supply_geq_zero(e: Env) {
    assume_pre_total_supply_geq_zero(&e);
    let shares: i64 = nondet();
    clog!(shares);
    let receiver: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&receiver));
    let from: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&from));
    let operator: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&operator));
    BasicVault::mint(&e, shares, receiver, from, operator);
    assert_post_total_supply_geq_zero(&e);
}

#[rule]
// invariant: total_supply >= 0, case: withdraw
// status: verified
// link: https://prover.certora.com/output/5771024/5836f2b6cde24450a77131f33ce5a77b/?anonymousKey=d73db7c427056cffec889b0e36ad6d405a9384bf
pub fn after_withdraw_total_supply_geq_zero(e: Env) {
    assume_pre_total_supply_geq_zero(&e);
    assume_pre_solvency(&e); // add this line
    let shares: i64 = nondet();
    clog!(shares);
    let receiver: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&receiver));
    let owner: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&owner));
    let operator: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&operator));
    assume_pre_total_supply_geq_balance(&e, &owner);
    BasicVault::withdraw(&e, shares, receiver, owner, operator);
    assert_post_total_supply_geq_zero(&e);
}

#[rule]
// invariant: total_supply >= 0, case: redeem
// status: verified
// link: https://prover.certora.com/output/5771024/00181087e94a446e8b91442daf9e4c99?anonymousKey=0dfc4d7085b7a3e977ff22f67af84a7a1f4356b9
pub fn after_redeem_total_supply_geq_zero(e: Env) {
    assume_pre_total_supply_geq_zero(&e);
    let shares: i64 = nondet();
    clog!(shares);
    let receiver: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&receiver));
    let owner: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&owner));
    let operator: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&operator));
    assume_pre_total_supply_geq_balance(&e, &owner);
    BasicVault::redeem(&e, shares, receiver, owner, operator);
    assert_post_total_supply_geq_zero(&e);
}

#[rule]
// invariant: total_supply >= 0, case: set_asset
// status: verified
// link: https://prover.certora.com/output/5771024/5836f2b6cde24450a77131f33ce5a77b/?anonymousKey=d73db7c427056cffec889b0e36ad6d405a9384bf
pub fn after_set_asset_total_supply_geq_zero(e: Env) {
    assume_pre_total_supply_geq_zero(&e);
    let asset: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&asset));
    Vault::set_asset(&e, asset);
    assert_post_total_supply_geq_zero(&e);
}

#[rule]
// invariant: total_supply >= 0, case: set_decimals_offset
// status: verified
// link: https://prover.certora.com/output/5771024/5836f2b6cde24450a77131f33ce5a77b/?anonymousKey=d73db7c427056cffec889b0e36ad6d405a9384bf
pub fn after_set_decimals_offset_total_supply_geq_zero(e: Env) {
    assume_pre_total_supply_geq_zero(&e);
    let offset: u32 = nondet();
    clog!(offset);
    Vault::set_decimals_offset(&e, offset);
    assert_post_total_supply_geq_zero(&e);
}

#[rule]
// invariant: total_supply >= 0, case: token_transfer
// status: verified
// link: https://prover.certora.com/output/5771024/5836f2b6cde24450a77131f33ce5a77b/?anonymousKey=d73db7c427056cffec889b0e36ad6d405a9384bf
pub fn after_token_transfer_total_supply_geq_zero(e: Env) {
    assume_pre_total_supply_geq_zero(&e);
    let from: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&from));
    let to: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&to));
    let amount: i64 = nondet();
    clog!(amount);
    AssetToken::transfer(&e, from, to, amount);
    assert_post_total_supply_geq_zero(&e);
}

#[rule]
// invariant: total_supply >= 0, case: token_transfer_from
// status: verified
// link: https://prover.certora.com/output/57771024/5836f2b6cde24450a77131f33ce5a77b/?anonymousKey=d73db7c427056cffec889b0e36ad6d405a9384bf
pub fn after_token_transfer_from_total_supply_geq_zero(e: Env) {
    assume_pre_total_supply_geq_zero(&e);
    let spender: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&spender));
    let from: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&from));
    let to: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&to));
    let amount: i64 = nondet();
    clog!(amount);
    AssetToken::transfer_from(&e, spender, from, to, amount);
    assert_post_total_supply_geq_zero(&e);
}

#[rule]
// invariant: total_supply >= 0, case: token_approve
// status: verified
// link: https://prover.certora.com/output/5771024/5836f2b6cde24450a77131f33ce5a77b/?anonymousKey=d73db7c427056cffec889b0e36ad6d405a9384bf
pub fn after_token_approve_total_supply_geq_zero(e: Env) {
    assume_pre_total_supply_geq_zero(&e);
    let owner: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&owner));
    let spender: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&spender));
    let amount: i64 = nondet();
    clog!(amount);
    let live_until_ledger: u32 = nondet();
    clog!(live_until_ledger);
    AssetToken::approve(&e, owner, spender, amount, live_until_ledger);
    assert_post_total_supply_geq_zero(&e);
}

// total_assets >= 0
// helpers

pub fn assume_pre_total_assets_geq_zero(e: &Env) {
    let total_assets = BasicVault::total_assets(e);
    clog!(total_assets);
    cvlr_assume!(total_assets >= 0);
}

pub fn assert_post_total_assets_geq_zero(e: &Env) {
    let total_assets = BasicVault::total_assets(e);
    clog!(total_assets);
    cvlr_assert!(total_assets >= 0);
}

#[rule]
// invariant: total_assets >= 0, case: transfer
// status: verified
// link: https://prover.certora.com/output/5771024/5836f2b6cde24450a77131f33ce5a77b/?anonymousKey=d73db7c427056cffec889b0e36ad6d405a9384bf
pub fn after_transfer_total_assets_geq_zero(e: Env) {
    assume_pre_total_assets_geq_zero(&e);
    let from = nondet_address();
    clog!(cvlr_soroban::Addr(&from));
    let to = nondet_address();
    clog!(cvlr_soroban::Addr(&to));
    let amount: i64 = nondet();
    clog!(amount);
    BasicVault::transfer(&e, from, to, amount);
    assert_post_total_assets_geq_zero(&e);
}

#[rule]
// invariant: total_assets >= 0, case: transfer_from
// status: verified
// link: https://prover.certora.com/output/5771024/5836f2b6cde24450a77131f33ce5a77b/?anonymousKey=d73db7c427056cffec889b0e36ad6d405a9384bf
pub fn after_transfer_from_total_assets_geq_zero(e: Env) {
    assume_pre_total_assets_geq_zero(&e);
    let spender = nondet_address();
    clog!(cvlr_soroban::Addr(&spender));
    let from = nondet_address();
    clog!(cvlr_soroban::Addr(&from));
    let to = nondet_address();
    clog!(cvlr_soroban::Addr(&to));
    let amount: i64 = nondet();
    clog!(amount);
    BasicVault::transfer_from(&e, spender, from, to, amount);
    assert_post_total_assets_geq_zero(&e);
}

#[rule]
// invariant: total_assets >= 0, case: approve
// status: verified
// link: https://prover.certora.com/output/5771024/5836f2b6cde24450a77131f33ce5a77b/?anonymousKey=d73db7c427056cffec889b0e36ad6d405a9384bf
pub fn after_approve_total_assets_geq_zero(e: Env) {
    assume_pre_total_assets_geq_zero(&e);
    let owner = nondet_address();
    clog!(cvlr_soroban::Addr(&owner));
    let spender = nondet_address();
    clog!(cvlr_soroban::Addr(&spender));
    let amount: i64 = nondet();
    clog!(amount);
    let live_until_ledger: u32 = nondet();
    clog!(live_until_ledger);
    BasicVault::approve(&e, owner, spender, amount, live_until_ledger);
    assert_post_total_assets_geq_zero(&e);
}

#[rule]
// invariant: total_assets >= 0, case: deposit
// status: verified
// link: https://prover.certora.com/output/5771024/5836f2b6cde24450a77131f33ce5a77b/?anonymousKey=d73db7c427056cffec889b0e36ad6d405a9384bf
// in a rerun with disable_split (48min)
// https://prover.certora.com/output/5771024/e3a269ef5d2547dfbadfdfadad55f238/
pub fn after_deposit_total_assets_geq_zero(e: Env) {
    assume_pre_total_assets_geq_zero(&e);
    let assets: i64 = nondet();
    clog!(assets);
    let receiver: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&receiver));
    let from: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&from));
    let operator: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&operator));
    BasicVault::deposit(&e, assets, receiver, from, operator);
    assert_post_total_assets_geq_zero(&e);
}

#[rule]
// invariant: total_assets >= 0, case: mint
// status: verified
// link: https://prover.certora.com/output/5771024/5836f2b6cde24450a77131f33ce5a77b/?anonymousKey=d73db7c427056cffec889b0e36ad6d405a9384bf
pub fn after_mint_total_assets_geq_zero(e: Env) {
    assume_pre_total_assets_geq_zero(&e);
    let shares: i64 = nondet();
    clog!(shares);
    let receiver: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&receiver));
    let from: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&from));
    let operator: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&operator));
    BasicVault::mint(&e, shares, receiver, from, operator);
    assert_post_total_assets_geq_zero(&e);
}

#[rule]
// invariant: total_assets >= 0, case: withdraw
// status: verified
// link: https://prover.certora.com/output/5771024/5836f2b6cde24450a77131f33ce5a77b/?anonymousKey=d73db7c427056cffec889b0e36ad6d405a9384bf
pub fn after_withdraw_total_assets_geq_zero(e: Env) {
    assume_pre_total_assets_geq_zero(&e);
    let shares: i64 = nondet();
    clog!(shares);
    let receiver: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&receiver));
    let owner: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&owner));
    let operator: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&operator));
    BasicVault::withdraw(&e, shares, receiver, owner, operator);
    assert_post_total_assets_geq_zero(&e);
}

#[rule]
// invariant: total_assets >= 0, case: redeem
// status: verified
// link: https://prover.certora.com/output/5771024/5836f2b6cde24450a77131f33ce5a77b/?anonymousKey=d73db7c427056cffec889b0e36ad6d405a9384bf
pub fn after_redeem_total_assets_geq_zero(e: Env) {
    assume_pre_total_assets_geq_zero(&e);
    let shares: i64 = nondet();
    clog!(shares);
    let receiver: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&receiver));
    let owner: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&owner));
    let operator: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&operator));
    BasicVault::redeem(&e, shares, receiver, owner, operator);
    assert_post_total_assets_geq_zero(&e);
}

#[rule]
// invariant: total_assets >= 0, case: set_asset
// status: verified
// link: https://prover.certora.com/output/5771024/5836f2b6cde24450a77131f33ce5a77b/?anonymousKey=d73db7c427056cffec889b0e36ad6d405a9384bfa
pub fn after_set_asset_total_assets_geq_zero(e: Env) {
    assume_pre_total_assets_geq_zero(&e);
    let asset: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&asset));
    Vault::set_asset(&e, asset);
    assert_post_total_assets_geq_zero(&e);
}

#[rule]
// invariant: total_assets >= 0, case: set_decimals_offset
// status: verified
// link: https://prover.certora.com/output/5771024/5836f2b6cde24450a77131f33ce5a77b/?anonymousKey=d73db7c427056cffec889b0e36ad6d405a9384bf
pub fn after_set_decimals_offset_total_assets_geq_zero(e: Env) {
    assume_pre_total_assets_geq_zero(&e);
    let offset: u32 = nondet();
    clog!(offset);
    Vault::set_decimals_offset(&e, offset);
    assert_post_total_assets_geq_zero(&e);
}

#[rule]
// invariant: total_assets >= 0, case: token_transfer
// status: verified
// link: https://prover.certora.com/output/5771024/5836f2b6cde24450a77131f33ce5a77b/?anonymousKey=d73db7c427056cffec889b0e36ad6d405a9384bf
pub fn after_token_transfer_total_assets_geq_zero(e: Env) {
    assume_pre_total_assets_geq_zero(&e);
    let from: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&from));
    let to: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&to));
    let amount: i64 = nondet();
    clog!(amount);
    AssetToken::transfer(&e, from, to, amount);
    assert_post_total_assets_geq_zero(&e);
}

#[rule]
// invariant: total_assets >= 0, case: token_transfer_from
// status: verified
// link: https://prover.certora.com/output/5771024/5836f2b6cde24450a77131f33ce5a77b/?anonymousKey=d73db7c427056cffec889b0e36ad6d405a9384bf
pub fn after_token_transfer_from_total_assets_geq_zero(e: Env) {
    assume_pre_total_assets_geq_zero(&e);
    let spender: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&spender));
    let from: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&from));
    let to: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&to));
    let amount: i64 = nondet();
    clog!(amount);
    AssetToken::transfer_from(&e, spender, from, to, amount);
    assert_post_total_assets_geq_zero(&e);
}

#[rule]
// invariant: total_assets >= 0, case: token_approve
// status: verified
// link: https://prover.certora.com/output/5771024/5836f2b6cde24450a77131f33ce5a77b/?anonymousKey=d73db7c427056cffec889b0e36ad6d405a9384bf
pub fn after_token_approve_total_assets_geq_zero(e: Env) {
    assume_pre_total_assets_geq_zero(&e);
    let owner: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&owner));
    let spender: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&spender));
    let amount: i64 = nondet();
    clog!(amount);
    let live_until_ledger: u32 = nondet();
    clog!(live_until_ledger);
    AssetToken::approve(&e, owner, spender, amount, live_until_ledger);
    assert_post_total_assets_geq_zero(&e);
}
