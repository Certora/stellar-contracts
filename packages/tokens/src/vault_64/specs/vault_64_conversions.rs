use cvlr::{clog, cvlr_assert, cvlr_assume, cvlr_satisfy, nondet::*};
use cvlr_soroban::nondet_address;
use cvlr_soroban_derive::rule;
use soroban_sdk::{Address, Env};
use stellar_contract_utils::math::fixed_point::Rounding;

use super::{vault_64_invariants::safe_assumptions, vault_64_solvency::assume_pre_solvency};
use crate::vault_64::{
    fungible_64::FungibleToken,
    specs::{asset_token::AssetToken, vault::BasicVault},
    FungibleVault, Vault,
};

pub fn useful_clogs(e: &Env) {
    let total_assets = BasicVault::total_assets(e);
    clog!(total_assets);
    let total_supply = BasicVault::total_supply(e);
    clog!(total_supply);
    let decimals_offset = Vault::get_decimals_offset(e);
    clog!(decimals_offset);
}

#[rule]
// convert to shares of 0 assets gives 0 shares.
// status: verified
// link: https://prover.certora.com/output/5771024/f076cf2ca6004e2b98409bd6cff70db2/?anonymousKey=5af298988f28ed1d968593dcbf2c6f219344f220
pub fn convert_to_shares_zero_to_zero(e: Env) {
    safe_assumptions(&e);
    let assets: i64 = nondet();
    clog!(assets);
    let shares = BasicVault::convert_to_shares(&e, assets);
    clog!(shares);
    let assets_are_zero = assets == 0;
    clog!(assets_are_zero);
    let shares_are_zero = shares == 0;
    clog!(shares_are_zero);
    if assets_are_zero {
        cvlr_assert!(shares_are_zero);
    }
}

#[rule]
// convert to assets returns 0 if and only if input is 0
// status: verified
// link: https://prover.certora.com/output/5771024/f076cf2ca6004e2b98409bd6cff70db2/?anonymousKey=5af298988f28ed1d968593dcbf2c6f219344f220
pub fn convert_to_assets_zero_to_zero(e: Env) {
    safe_assumptions(&e);
    let shares: i64 = 0;
    clog!(shares);
    let assets = BasicVault::convert_to_assets(&e, shares);
    clog!(assets);
    let shares_are_zero = shares == 0;
    clog!(shares_are_zero);
    let assets_are_zero = assets == 0;
    clog!(assets_are_zero);
    cvlr_assert!(shares_are_zero == assets_are_zero);
}

#[rule]
// convert to shares monotonicty
// status: verified
// link: https://prover.certora.com/output/5771024/f076cf2ca6004e2b98409bd6cff70db2/?anonymousKey=5af298988f28ed1d968593dcbf2c6f219344f220
pub fn convert_to_shares_monotonicity(e: Env) {
    safe_assumptions(&e);
    let assets1: i64 = nondet();
    let assets2: i64 = nondet();
    cvlr_assume!(assets1 >= 0);
    cvlr_assume!(assets2 >= 0);
    cvlr_assume!(assets1 >= i64::MIN as i64 && assets1 <= i64::MAX as i64);
    cvlr_assume!(assets2 >= i64::MIN as i64 && assets2 <= i64::MAX as i64);
    clog!(assets1);
    clog!(assets2);
    cvlr_assume!(assets1 <= assets2);
    let shares1 = BasicVault::convert_to_shares(&e, assets1);
    let shares2 = BasicVault::convert_to_shares(&e, assets2);
    clog!(shares1);
    clog!(shares2);
    cvlr_assert!(shares1 <= shares2);
}

#[rule]
// convert to assets monotonicity
// status: verified
// link: https://prover.certora.com/output/5771024/f076cf2ca6004e2b98409bd6cff70db2/?anonymousKey=5af298988f28ed1d968593dcbf2c6f219344f220
pub fn convert_to_assets_monotonicity(e: Env) {
    safe_assumptions(&e);
    let shares1: i64 = nondet();
    let shares2: i64 = nondet();
    cvlr_assume!(shares1 >= i64::MIN as i64 && shares1 <= i64::MAX as i64);
    cvlr_assume!(shares2 >= i64::MIN as i64 && shares2 <= i64::MAX as i64);
    clog!(shares1);
    clog!(shares2);
    cvlr_assume!(shares1 <= shares2);
    let assets1 = BasicVault::convert_to_assets(&e, shares1);
    let assets2 = BasicVault::convert_to_assets(&e, shares2);
    clog!(assets1);
    clog!(assets2);
    cvlr_assert!(assets1 <= assets2);
}

#[rule]
// convert to shares weak inverse
// status: verified
// link: https://prover.certora.com/output/5771024/f076cf2ca6004e2b98409bd6cff70db2/?anonymousKey=5af298988f28ed1d968593dcbf2c6f219344f220
pub fn convert_to_shares_weak_inverse(e: Env) {
    safe_assumptions(&e);
    let assets: i64 = nondet();
    cvlr_assume!(assets >= i64::MIN as i64 && assets <= i64::MAX as i64);
    clog!(assets);
    let shares_from_assets = BasicVault::convert_to_shares(&e, assets);
    clog!(shares_from_assets);
    let assets_from_shares_from_assets = BasicVault::convert_to_assets(&e, shares_from_assets);
    clog!(assets_from_shares_from_assets);
    cvlr_assert!(assets_from_shares_from_assets <= assets);
}

#[rule]
// convert to assets weak inverse
// status: verified
// link: https://prover.certora.com/output/5771024/f076cf2ca6004e2b98409bd6cff70db2/?anonymousKey=5af298988f28ed1d968593dcbf2c6f219344f220
pub fn convert_to_assets_weak_inverse(e: Env) {
    safe_assumptions(&e);
    let shares: i64 = nondet();
    cvlr_assume!(shares >= i64::MIN as i64 && shares <= i64::MAX as i64);
    clog!(shares);
    let assets_from_shares = BasicVault::convert_to_assets(&e, shares);
    clog!(assets_from_shares);
    let shares_from_assets_from_shares = BasicVault::convert_to_shares(&e, assets_from_shares);
    clog!(shares_from_assets_from_shares);
    cvlr_assert!(shares_from_assets_from_shares <= shares);
}

#[rule]
// deposit matches preview_deposit
// status: verified
// link: https://prover.certora.com/output/5771024/25afa1dfb34d421ab0f67fcd66096fa6/?anonymousKey=a1793edb5a4fc64275de51392c517a2802f67f37
pub fn deposit_matches_preview_deposit(e: Env) {
    safe_assumptions(&e);
    let assets: i64 = nondet();
    cvlr_assume!(assets >= i64::MIN as i64 && assets <= i64::MAX as i64);
    clog!(assets);
    let preview_deposit = BasicVault::preview_deposit(&e, assets);
    clog!(preview_deposit);
    let receiver: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&receiver));
    let from: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&from));
    let operator: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&operator));
    let shares = BasicVault::deposit(&e, assets, receiver, from, operator);
    clog!(shares);
    cvlr_assert!(shares == preview_deposit);
}

#[rule]
// withdraw matches preview_withdraw
// status: verified
// link: https://prover.certora.com/output/33158/1fe846c0d58c40298cabc0e047815f30/
pub fn withdraw_matches_preview_withdraw(e: Env) {
    safe_assumptions(&e);
    let assets: i64 = nondet();
    cvlr_assume!(assets >= i64::MIN as i64 && assets <= i64::MAX as i64);
    clog!(assets);
    let preview_withdraw = BasicVault::preview_withdraw(&e, assets);
    clog!(preview_withdraw);
    let receiver: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&receiver));
    let owner: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&owner));
    let operator: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&operator));
    let shares = BasicVault::withdraw(&e, assets, receiver, owner, operator);
    clog!(shares);
    cvlr_assert!(shares == preview_withdraw);
}

#[rule]
// mint matches preview_mint
// status: verified
// link: https://prover.certora.com/output/33158/0a037865a74a4873a11d0189d58f5f4e
pub fn mint_matches_preview_mint(e: Env) {
    safe_assumptions(&e);
    let shares: i64 = nondet();
    cvlr_assume!(shares >= i64::MIN as i64 && shares <= i64::MAX as i64);
    clog!(shares);
    let preview_mint = BasicVault::preview_mint(&e, shares);
    clog!(preview_mint);
    let receiver: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&receiver));
    let from: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&from));
    let operator: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&operator));
    let assets = BasicVault::mint(&e, shares, receiver, from, operator);
    clog!(assets);
    cvlr_assert!(assets == preview_mint);
}

#[rule]
// redeem matches preview_redeem
// status: verified
// link: https://prover.certora.com/output/33158/a20efc21cd82407a906b10ec4edfde0a
pub fn redeem_matches_preview_redeem(e: Env) {
    safe_assumptions(&e);
    let shares: i64 = nondet();
    cvlr_assume!(shares >= i64::MIN as i64 && shares <= i64::MAX as i64);
    clog!(shares);
    let preview_redeem = BasicVault::preview_redeem(&e, shares);
    clog!(preview_redeem);
    let receiver: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&receiver));
    let owner: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&owner));
    let operator: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&operator));
    let assets = BasicVault::redeem(&e, shares, receiver, owner, operator);
    clog!(assets);
    cvlr_assert!(assets == preview_redeem);
}
