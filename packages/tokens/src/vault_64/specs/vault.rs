use soroban_sdk::{Address, Env};

use crate::vault_64::{
    fungible_64::{ContractOverrides, FungibleToken},
    FungibleVault, Vault,
};
pub struct BasicVault;

impl FungibleToken for BasicVault {
    type ContractType = Vault;

    fn total_supply(e: &Env) -> i64 {
        Vault::total_supply(e)
    }

    fn balance(e: &Env, account: Address) -> i64 {
        Vault::balance(e, &account)
    }

    fn allowance(e: &Env, owner: Address, spender: Address) -> i64 {
        Vault::allowance(e, &owner, &spender)
    }

    fn transfer(e: &Env, from: Address, to: Address, amount: i64) {
        Vault::transfer(e, &from, &to, amount);
    }

    fn transfer_from(e: &Env, spender: Address, from: Address, to: Address, amount: i64) {
        Vault::transfer_from(e, &spender, &from, &to, amount);
    }

    fn approve(e: &Env, owner: Address, spender: Address, amount: i64, live_until_ledger: u32) {
        Vault::approve(e, &owner, &spender, amount, live_until_ledger);
    }

    fn decimals(e: &Env) -> u32 {
        Vault::decimals(e)
    }

    fn name(e: &Env) -> soroban_sdk::String {
        Vault::name(e)
    }

    fn symbol(e: &Env) -> soroban_sdk::String {
        Vault::symbol(e)
    }
}

// TODO: do we need require_auth? The `fungible_vault` example has it.

impl FungibleVault for BasicVault {
    fn query_asset(e: &Env) -> Address {
        Vault::query_asset(e)
    }

    fn total_assets(e: &Env) -> i64 {
        Vault::total_assets(e)
    }

    fn convert_to_shares(e: &Env, assets: i64) -> i64 {
        Vault::convert_to_shares(e, assets)
    }

    fn convert_to_assets(e: &Env, shares: i64) -> i64 {
        Vault::convert_to_assets(e, shares)
    }

    fn max_deposit(e: &Env, receiver: Address) -> i64 {
        Vault::max_deposit(e, receiver)
    }

    fn preview_deposit(e: &Env, assets: i64) -> i64 {
        Vault::preview_deposit(e, assets)
    }

    fn deposit(e: &Env, assets: i64, receiver: Address, from: Address, operator: Address) -> i64 {
        Vault::deposit(e, assets, receiver, from, operator)
    }

    fn max_mint(e: &Env, receiver: Address) -> i64 {
        Vault::max_mint(e, receiver)
    }

    fn preview_mint(e: &Env, shares: i64) -> i64 {
        Vault::preview_mint(e, shares)
    }

    fn mint(e: &Env, shares: i64, receiver: Address, from: Address, operator: Address) -> i64 {
        Vault::mint(e, shares, receiver, from, operator)
    }

    fn max_withdraw(e: &Env, owner: Address) -> i64 {
        Vault::max_withdraw(e, owner)
    }

    fn preview_withdraw(e: &Env, assets: i64) -> i64 {
        Vault::preview_withdraw(e, assets)
    }

    fn withdraw(e: &Env, assets: i64, receiver: Address, owner: Address, operator: Address) -> i64 {
        Vault::withdraw(e, assets, receiver, owner, operator)
    }

    fn max_redeem(e: &Env, owner: Address) -> i64 {
        Vault::max_redeem(e, owner)
    }

    fn preview_redeem(e: &Env, shares: i64) -> i64 {
        Vault::preview_redeem(e, shares)
    }

    fn redeem(e: &Env, shares: i64, receiver: Address, owner: Address, operator: Address) -> i64 {
        Vault::redeem(e, shares, receiver, owner, operator)
    }
}
