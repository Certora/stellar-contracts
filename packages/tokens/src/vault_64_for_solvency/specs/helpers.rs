use cvlr::{clog, cvlr_assert, cvlr_assume};
use soroban_sdk::{panic_with_error, Env};

use crate::vault_64_for_solvency::{fungible_64::FungibleToken, specs::vault::BasicVault, storage::Vault, *};

pub fn effective_total_assets(e: &Env) -> i64 {
    let total_assets = BasicVault::total_assets(e);
    clog!(total_assets);
    if total_assets == i64::MAX {
        panic_with_error!(e, VaultTokenError::MathOverflow);
    }
    let effective_total_assets = total_assets + 1;
    clog!(effective_total_assets);
    effective_total_assets
}

pub fn virtual_offset(e: &Env) -> i64 {
    let decimals_offset = Vault::get_decimals_offset(e);
    clog!(decimals_offset);
    // let virtual_offset = 10_i64
    //     .checked_pow(decimals_offset)
    //     .unwrap_or_else(|| panic_with_error!(e, VaultTokenError::MathOverflow));
    let virtual_offset = 1_i64;
    clog!(virtual_offset);
    virtual_offset
}

pub fn effective_total_supply(e: &Env) -> i64 {
    let total_supply = BasicVault::total_supply(e);
    clog!(total_supply);
    if total_supply == i64::MAX {
        panic_with_error!(e, VaultTokenError::MathOverflow);
    }
    let virtual_offset = virtual_offset(e);
    clog!(virtual_offset);

    // let effective_total_supply = total_supply
    //     .checked_add(virtual_offset)
    //     .unwrap_or_else(|| panic_with_error!(e, VaultTokenError::MathOverflow));

    let effective_total_supply = {
        if total_supply + virtual_offset > i64::MAX {
            panic_with_error!(e, VaultTokenError::MathOverflow);
        }
        total_supply + virtual_offset
    };
    clog!(effective_total_supply);
    effective_total_supply
}

pub fn safe_assumptions(e: &Env) {
    assume_pre_total_supply_geq_zero(e);
    assume_pre_total_assets_geq_zero(e);
}

pub fn assume_pre_total_supply_geq_zero(e: &Env) {
    let total_supply = BasicVault::total_supply(e);
    clog!(total_supply);
    cvlr_assume!(total_supply >= 0);
}

pub fn assume_pre_total_assets_geq_zero(e: &Env) {
    let total_assets = BasicVault::total_assets(e);
    clog!(total_assets);
    cvlr_assume!(total_assets >= 0);
}


pub fn assert_post_total_supply_geq_zero(e: &Env) {
    let total_supply = BasicVault::total_supply(e);
    clog!(total_supply);
    cvlr_assert!(total_supply >= 0);
}
