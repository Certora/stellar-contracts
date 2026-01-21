use soroban_sdk::{contract, contractimpl, Address, Env, String};
use crate::vault_64_for_solvency::fungible_64::{FungibleToken, overrides::Base};

pub struct AssetToken<'a> {
    pub asset: &'a Address,
}

impl<'a> AssetToken<'a> {
    pub fn __constructor(e: &Env, addr: &'a Address) -> AssetToken<'a> {
        return AssetToken { asset: addr };
    }
}

impl<'a> FungibleToken for AssetToken<'a> {
    type ContractType = Base;

    fn total_supply(e: &Env) -> i64 {
        Base::total_supply(e)
    }

    fn balance(e: &Env, account: Address) -> i64 {
        Base::balance(e, &account)
    }

    fn allowance(e: &Env, owner: Address, spender: Address) -> i64 {
        Base::allowance(e, &owner, &spender)
    }

    fn transfer(e: &Env, from: Address, to: Address, amount: i64) {
        Base::transfer(e, &from, &to, amount);
    }

    fn transfer_from(e: &Env, spender: Address, from: Address, to: Address, amount: i64) {
        Base::transfer_from(e, &spender, &from, &to, amount);
    }

    fn approve(e: &Env, owner: Address, spender: Address, amount: i64, live_until_ledger: u32) {
        Base::approve(e, &owner, &spender, amount, live_until_ledger);
    }

    fn decimals(e: &Env) -> u32 {
        Base::decimals(e)
    }

    fn name(e: &Env) -> String {
        Base::name(e)
    }

    fn symbol(e: &Env) -> String {
        Base::symbol(e)
    }
}
