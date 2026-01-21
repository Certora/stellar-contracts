pub mod storage;
pub mod fungible_64;

#[cfg(test)]
mod test;

#[cfg(feature = "certora")]
pub mod specs;

#[cfg(feature = "certora")]
use cvlr_soroban_derive::contractevent;
#[cfg(not(feature = "certora"))]
use soroban_sdk::contractevent;
use soroban_sdk::{contracterror, Address, Env};

use crate::vault_64_for_solvency::fungible_64::FungibleToken;
use crate::vault_64_for_solvency::storage::Vault;

// 64 bit version of the vault for formal verification purposes

pub trait FungibleVault: FungibleToken<ContractType = Vault> {
    fn query_asset(e: &Env) -> Address;

    fn total_assets(e: &Env) -> i64;

    fn convert_to_shares(e: &Env, assets: i64) -> i64;

    fn convert_to_assets(e: &Env, shares: i64) -> i64;

    fn max_deposit(e: &Env, receiver: Address) -> i64;

    fn preview_deposit(e: &Env, assets: i64) -> i64;

    fn deposit(e: &Env, assets: i64, receiver: Address, from: Address, operator: Address) -> i64;

    fn max_mint(e: &Env, receiver: Address) -> i64;

    fn preview_mint(e: &Env, shares: i64) -> i64;

    fn mint(e: &Env, shares: i64, receiver: Address, from: Address, operator: Address) -> i64;

    fn max_withdraw(e: &Env, owner: Address) -> i64;

    fn preview_withdraw(e: &Env, assets: i64) -> i64;

    fn withdraw(
        e: &Env,
        assets: i64,
        receiver: Address,
        owner: Address,
        operator: Address,
    ) -> i64;

    fn max_redeem(e: &Env, owner: Address) -> i64;

    fn preview_redeem(e: &Env, shares: i64) -> i64;

    fn redeem(e: &Env, shares: i64, receiver: Address, owner: Address, operator: Address) -> i64;
}

// ################## ERRORS ##################

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum VaultTokenError {
    /// Indicates access to uninitialized vault asset address.
    VaultAssetAddressNotSet = 400,
    /// Indicates that vault asset address is already set.
    VaultAssetAddressAlreadySet = 401,
    /// Indicates that vault virtual decimals offset is already set.
    VaultVirtualDecimalsOffsetAlreadySet = 402,
    /// Indicates the amount is not a valid vault assets value.
    VaultInvalidAssetsAmount = 403,
    /// Indicates the amount is not a valid vault shares value.
    VaultInvalidSharesAmount = 404,
    /// Attempted to deposit more assets than the max amount for address.
    VaultExceededMaxDeposit = 405,
    /// Attempted to mint more shares than the max amount for address.
    VaultExceededMaxMint = 406,
    /// Attempted to withdraw more assets than the max amount for address.
    VaultExceededMaxWithdraw = 407,
    /// Attempted to redeem more shares than the max amount for address.
    VaultExceededMaxRedeem = 408,
    /// Maximum number of decimals offset exceeded
    VaultMaxDecimalsOffsetExceeded = 409,
    /// Indicates overflow due to mathematical operations
    MathOverflow = 410,
}

// ################## CONSTANTS ##################

// Suggested upper-bound for decimals to maximize both security and UX
pub const MAX_DECIMALS_OFFSET: u32 = 10;

// ################## EVENTS ##################

/// Event emitted when underlying assets are deposited into the vault.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Deposit {
    #[topic]
    pub operator: Address,
    #[topic]
    pub from: Address,
    #[topic]
    pub receiver: Address,
    pub assets: i64,
    pub shares: i64,
}

/// Emits an event when underlying assets are deposited into the vault in
/// exchange for shares.
///
/// # Arguments
///
/// * `e` - Access to Soroban environment.
/// * `operator` - The address that initiated the deposit transaction.
/// * `from` - The address that will provide the underlying assets.
/// * `receiver` - The address that will own the vault shares being minted.
/// * `assets` - The amount of underlying assets being deposited into the vault.
/// * `shares` - The amount of vault shares being minted in exchange for the
///   assets.
#[cfg(not(feature = "certora"))]
pub fn emit_deposit(
    e: &Env,
    operator: &Address,
    from: &Address,
    receiver: &Address,
    assets: i64,
    shares: i64,
) {
    Deposit {
        operator: operator.clone(),
        from: from.clone(),
        receiver: receiver.clone(),
        assets,
        shares,
    }
    .publish(e);
}

/// Event emitted when shares are exchanged back for underlying assets.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Withdraw {
    #[topic]
    pub operator: Address,
    #[topic]
    pub receiver: Address,
    #[topic]
    pub owner: Address,
    pub assets: i64,
    pub shares: i64,
}

/// Emits an event when shares are exchanged back for underlying assets and
/// assets are withdrawn from the vault.
///
/// # Arguments
///
/// * `e` - Access to Soroban environment.
/// * `operator` - The address that initiated the withdrawal transaction.
/// * `receiver` - The address that will receive the underlying assets being
///   withdrawn.
/// * `owner` - The address that owns the vault shares being burned.
/// * `assets` - The amount of underlying assets being withdrawn from the vault.
/// * `shares` - The amount of vault shares being burned in exchange for the
///   assets.
#[cfg(not(feature = "certora"))]
pub fn emit_withdraw(
    e: &Env,
    operator: &Address,
    receiver: &Address,
    owner: &Address,
    assets: i64,
    shares: i64,
) {
    Withdraw {
        operator: operator.clone(),
        receiver: receiver.clone(),
        owner: owner.clone(),
        assets,
        shares,
    }
    .publish(e);
}
