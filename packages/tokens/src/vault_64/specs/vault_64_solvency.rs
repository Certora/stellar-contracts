use cvlr::{clog, cvlr_assert, cvlr_assume, cvlr_satisfy, nondet::*};
use cvlr_soroban::nondet_address;
use cvlr_soroban_derive::rule;
use soroban_sdk::{Address, Env};
use stellar_contract_utils::math::fixed_point::Rounding;

use crate::vault_64::specs::helpers::{effective_total_assets, effective_total_supply, safe_assumptions};
use crate::vault_64::{
    specs::{asset_token::AssetToken, vault::BasicVault},
    FungibleVault, Vault,
};
use crate::vault_64::fungible_64::FungibleToken;

// invariant: effective total assets >= effective total supply

// helpers

pub fn assume_pre_solvency(e: &Env) {
    let total_assets = effective_total_assets(e);
    clog!(total_assets);
    let total_supply = effective_total_supply(e);
    clog!(total_supply);
    cvlr_assume!(total_assets >= total_supply);
}
