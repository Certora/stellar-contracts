use cvlr::{clog, cvlr_assert, cvlr_satisfy, nondet::*};
use cvlr_soroban::nondet_address;
use cvlr_soroban_derive::rule;
use soroban_sdk::{Address, Env};
use stellar_contract_utils::math::Rounding;

use super::vault_64_invariants::safe_assumptions;
use crate::vault_64::{
    fungible_64::FungibleToken,
    specs::{asset_token::AssetToken, vault::BasicVault},
    FungibleVault, Vault,
};
// integrity rules for all functions of the vault.

// property: P-XX. Vault-Integrity.
// description: Vault functions change state as expected.
// status: verified

#[rule]
// set_asset sets the asset address in storage
// status: verified
pub fn set_asset_integrity(e: Env) {
    let new_asset_address: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&new_asset_address.clone()));
    Vault::set_asset(&e, new_asset_address.clone());
    let asset_address_post = Vault::query_asset(&e);
    clog!(cvlr_soroban::Addr(&asset_address_post));
    cvlr_assert!(asset_address_post == new_asset_address);
}

#[rule]
// set_decimals_offset sets the decimals offset in storage
// status: verified
pub fn set_decimals_offset_integrity(e: Env) {
    let new_decimals_offset: u32 = nondet();
    clog!(new_decimals_offset);
    Vault::set_decimals_offset(&e, new_decimals_offset.clone());
    let decimals_offset_post = Vault::get_decimals_offset(&e);
    clog!(decimals_offset_post);
    cvlr_assert!(decimals_offset_post == new_decimals_offset);
}

#[rule]
// deposit does not increase the asset balance of the from account
// status: verified
pub fn deposit_integrity_1(e: Env) {
    safe_assumptions(&e);
    let assets: i64 = nondet();
    clog!(assets);
    let receiver: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&receiver));
    let from: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&from));
    let operator: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&operator));
    let assets_from_pre = AssetToken::balance(&e, from.clone());
    clog!(assets_from_pre);
    let shares = BasicVault::deposit(&e, assets, receiver.clone(), from.clone(), operator.clone());
    clog!(shares);
    let assets_from_post = AssetToken::balance(&e, from.clone());
    clog!(assets_from_post);
    cvlr_assert!(assets_from_post <= assets_from_pre);
}

#[rule]
// deposit does not decrease the shares balance of the receiver
// status: verified
pub fn deposit_integrity_2(e: Env) {
    safe_assumptions(&e);
    let assets: i64 = nondet();
    clog!(assets);
    let receiver: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&receiver));
    let from: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&from));
    let operator: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&operator));
    let shares_receiver_pre = BasicVault::balance(&e, receiver.clone());
    clog!(shares_receiver_pre);
    let shares_receiver_post = BasicVault::balance(&e, receiver.clone());
    clog!(shares_receiver_post);
    cvlr_assert!(shares_receiver_post >= shares_receiver_pre);
}

#[rule]
// deposit does not increase total_assets
// status: verified
pub fn deposit_integrity_3(e: Env) {
    safe_assumptions(&e);
    let assets: i64 = nondet();
    clog!(assets);
    let receiver: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&receiver));
    let from: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&from));
    let operator: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&operator));
    let total_assets_pre = BasicVault::total_assets(&e);
    clog!(total_assets_pre);
    let shares = BasicVault::deposit(&e, assets, receiver.clone(), from.clone(), operator.clone());
    clog!(shares);
    let total_assets_post = BasicVault::total_assets(&e);
    clog!(total_assets_post);
    cvlr_assert!(total_assets_post >= total_assets_pre);
}

#[rule]
// deposit does not decrease the shares balance of the receiver
// status: verified
pub fn deposit_integrity_4(e: Env) {
    safe_assumptions(&e);
    let assets: i64 = nondet();
    clog!(assets);
    let receiver: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&receiver));
    let from: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&from));
    let operator: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&operator));
    let shares_receiver_pre = BasicVault::balance(&e, receiver.clone());
    clog!(shares_receiver_pre);
    let shares = BasicVault::deposit(&e, assets, receiver.clone(), from.clone(), operator.clone());
    clog!(shares);
    let shares_receiver_post = BasicVault::balance(&e, receiver.clone());
    clog!(shares_receiver_post);
    cvlr_assert!(shares_receiver_post >= shares_receiver_pre);
}

#[rule]
// withdraw decreases the shares balance of owner by the shares returned
// status: verified
pub fn withdraw_integrity_1(e: Env) {
    safe_assumptions(&e);
    let assets: i64 = nondet();
    clog!(assets);
    let receiver: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&receiver));
    let owner: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&owner));
    let operator: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&operator));
    let shares_owner_pre = BasicVault::balance(&e, owner.clone());
    clog!(shares_owner_pre);
    let shares =
        BasicVault::withdraw(&e, assets, receiver.clone(), owner.clone(), operator.clone());
    clog!(shares);
    let shares_owner_post = BasicVault::balance(&e, owner.clone());
    clog!(shares_owner_post);
    cvlr_assert!(shares_owner_post <= shares_owner_pre);
}

#[rule]
// withdraw does not increase the asset balance of the receiver
// status: verified
pub fn withdraw_integrity_2(e: Env) {
    safe_assumptions(&e);
    let assets: i64 = nondet();
    clog!(assets);
    let receiver: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&receiver));
    let owner: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&owner));
    let operator: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&operator));
    let assets_receiver_pre = AssetToken::balance(&e, receiver.clone());
    clog!(assets_receiver_pre);
    let shares =
        BasicVault::withdraw(&e, assets, receiver.clone(), owner.clone(), operator.clone());
    clog!(shares);
    let assets_receiver_post = AssetToken::balance(&e, receiver.clone());
    clog!(assets_receiver_post);
    cvlr_assert!(assets_receiver_post >= assets_receiver_pre);
}

#[rule]
// withdraw does not decrease total_assets
// status: verified
pub fn withdraw_integrity_3(e: Env) {
    safe_assumptions(&e);
    let assets: i64 = nondet();
    clog!(assets);
    let receiver: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&receiver));
    let owner: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&owner));
    let operator: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&operator));
    let total_assets_pre = BasicVault::total_assets(&e);
    clog!(total_assets_pre);
    let shares =
        BasicVault::withdraw(&e, assets, receiver.clone(), owner.clone(), operator.clone());
    clog!(shares);
    let total_assets_post = BasicVault::total_assets(&e);
    clog!(total_assets_post);
    cvlr_assert!(total_assets_post <= total_assets_pre);
}

#[rule]
// withdraw does not increase the shares balance of the owner
// status: verified
pub fn withdraw_integrity_4(e: Env) {
    safe_assumptions(&e);
    let assets: i64 = nondet();
    clog!(assets);
    let receiver: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&receiver));
    let owner: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&owner));
    let operator: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&operator));
    let shares_owner_pre = BasicVault::balance(&e, owner.clone());
    clog!(shares_owner_pre);
    let shares =
        BasicVault::withdraw(&e, assets, receiver.clone(), owner.clone(), operator.clone());
    clog!(shares);
    let shares_owner_post = BasicVault::balance(&e, owner.clone());
    clog!(shares_owner_post);
    cvlr_assert!(shares_owner_post <= shares_owner_pre);
}

#[rule]
// mint does not decrease the asset balance of the from account
// status: verified
pub fn mint_integrity_1(e: Env) {
    safe_assumptions(&e);
    let shares: i64 = nondet();
    clog!(shares);
    let receiver: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&receiver));
    let from: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&from));
    let operator: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&operator));
    let assets_from_pre = AssetToken::balance(&e, from.clone());
    clog!(assets_from_pre);
    let assets = BasicVault::mint(&e, shares, receiver.clone(), from.clone(), operator.clone());
    clog!(assets);
    let assets_from_post = AssetToken::balance(&e, from.clone());
    clog!(assets_from_post);
    cvlr_assert!(assets_from_post <= assets_from_pre);
}

#[rule]
// mint does not increase the shares balance of the receiver
// status: verified
pub fn mint_integrity_2(e: Env) {
    safe_assumptions(&e);
    let shares: i64 = nondet();
    clog!(shares);
    let receiver: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&receiver));
    let from: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&from));
    let operator: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&operator));
    let shares_receiver_pre = BasicVault::balance(&e, receiver.clone());
    clog!(shares_receiver_pre);
    let assets = BasicVault::mint(&e, shares, receiver.clone(), from.clone(), operator.clone());
    clog!(assets);
    let shares_receiver_post = BasicVault::balance(&e, receiver.clone());
    clog!(shares_receiver_post);
    cvlr_assert!(shares_receiver_post >= shares_receiver_pre);
}

#[rule]
// mint does not increase total_assets
// status: verified
pub fn mint_integrity_3(e: Env) {
    safe_assumptions(&e);
    let shares: i64 = nondet();
    clog!(shares);
    let receiver: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&receiver));
    let from: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&from));
    let operator: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&operator));
    let total_assets_pre = BasicVault::total_assets(&e);
    clog!(total_assets_pre);
    let assets = BasicVault::mint(&e, shares, receiver.clone(), from.clone(), operator.clone());
    clog!(assets);
    let total_assets_post = BasicVault::total_assets(&e);
    clog!(total_assets_post);
    cvlr_assert!(total_assets_post >= total_assets_pre);
}

#[rule]
// mint does not decrease the shares balance of the receiver
// status: verified
pub fn mint_integrity_4(e: Env) {
    safe_assumptions(&e);
    let shares: i64 = nondet();
    clog!(shares);
    let receiver: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&receiver));
    let from: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&from));
    let operator: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&operator));
    let shares_receiver_pre = BasicVault::balance(&e, receiver.clone());
    clog!(shares_receiver_pre);
    let assets = BasicVault::mint(&e, shares, receiver.clone(), from.clone(), operator.clone());
    clog!(assets);
    let shares_receiver_post = BasicVault::balance(&e, receiver.clone());
    clog!(shares_receiver_post);
    cvlr_assert!(shares_receiver_post >= shares_receiver_pre);
}

#[rule]
// redeem does not decrease the shares balance of the owner
// status: verified
pub fn redeem_integrity_1(e: Env) {
    safe_assumptions(&e);
    let shares: i64 = nondet();
    clog!(shares);
    let receiver: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&receiver));
    let owner: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&owner));
    let operator: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&operator));
    let shares_owner_pre = BasicVault::balance(&e, owner.clone());
    clog!(shares_owner_pre);
    let assets = BasicVault::redeem(&e, shares, receiver.clone(), owner.clone(), operator.clone());
    clog!(assets);
    let shares_owner_post = BasicVault::balance(&e, owner.clone());
    clog!(shares_owner_post);
    cvlr_assert!(shares_owner_post <= shares_owner_pre);
}

#[rule]
// redeem does not increase the asset balance of the receiver
// status: verified
pub fn redeem_integrity_2(e: Env) {
    safe_assumptions(&e);
    let shares: i64 = nondet();
    clog!(shares);
    let receiver: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&receiver));
    let owner: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&owner));
    let operator: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&operator));
    let assets_receiver_pre = AssetToken::balance(&e, receiver.clone());
    clog!(assets_receiver_pre);
    let assets = BasicVault::redeem(&e, shares, receiver.clone(), owner.clone(), operator.clone());
    clog!(assets);
    let assets_receiver_post = AssetToken::balance(&e, receiver.clone());
    clog!(assets_receiver_post);
    cvlr_assert!(assets_receiver_post >= assets_receiver_pre);
}

#[rule]
// redeem does not decrease total_assets
// status: verified
pub fn redeem_integrity_3(e: Env) {
    safe_assumptions(&e);
    let shares: i64 = nondet();
    clog!(shares);
    let receiver: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&receiver));
    let owner: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&owner));
    let operator: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&operator));
    let total_assets_pre = BasicVault::total_assets(&e);
    clog!(total_assets_pre);
    let assets = BasicVault::redeem(&e, shares, receiver.clone(), owner.clone(), operator.clone());
    clog!(assets);
    let total_assets_post = BasicVault::total_assets(&e);
    clog!(total_assets_post);
    cvlr_assert!(total_assets_post <= total_assets_pre);
}

#[rule]
// redeem does not increase the shares balance of the owner
// status: verified
pub fn redeem_integrity_4(e: Env) {
    safe_assumptions(&e);
    let shares: i64 = nondet();
    clog!(shares);
    let receiver: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&receiver));
    let owner: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&owner));
    let operator: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&operator));
    let shares_owner_pre = BasicVault::balance(&e, owner.clone());
    clog!(shares_owner_pre);
    let assets = BasicVault::redeem(&e, shares, receiver.clone(), owner.clone(), operator.clone());
    clog!(assets);
    let shares_owner_post = BasicVault::balance(&e, owner.clone());
    clog!(shares_owner_post);
    cvlr_assert!(shares_owner_post <= shares_owner_pre);
}
