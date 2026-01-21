// 64 bit version of fungible token for formal verification purposes

pub mod overrides;
pub mod storage;

#[cfg(test)]
mod test;

use soroban_sdk::{contracterror, Address, Env, String};
pub use storage::{AllowanceData, AllowanceKey, StorageKey};
pub use overrides::ContractOverrides;

#[cfg(feature = "certora")]
use cvlr_soroban_derive::contractevent;
#[cfg(not(feature = "certora"))]
use soroban_sdk::contractevent;


pub trait FungibleToken {

    type ContractType: ContractOverrides;

    fn total_supply(e: &Env) -> i64;

    fn balance(e: &Env, account: Address) -> i64;

    fn allowance(e: &Env, owner: Address, spender: Address) -> i64;

    fn transfer(e: &Env, from: Address, to: Address, amount: i64);

    fn transfer_from(e: &Env, spender: Address, from: Address, to: Address, amount: i64);

    fn approve(e: &Env, owner: Address, spender: Address, amount: i64, live_until_ledger: u32);

    fn decimals(e: &Env) -> u32;

    fn name(e: &Env) -> String;

    fn symbol(e: &Env) -> String;
}

// ################## ERRORS ##################

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum FungibleTokenError {
    /// Indicates an error related to the current balance of account from which
    /// tokens are expected to be transferred.
    InsufficientBalance = 100,
    /// Indicates a failure with the allowance mechanism when a given spender
    /// doesn't have enough allowance.
    InsufficientAllowance = 101,
    /// Indicates an invalid value for `live_until_ledger` when setting an
    /// allowance.
    InvalidLiveUntilLedger = 102,
    /// Indicates an error when an input that must be >= 0
    LessThanZero = 103,
    /// Indicates overflow when adding two values
    MathOverflow = 104,
    /// Indicates access to uninitialized metadata
    UnsetMetadata = 105,
    /// Indicates that the operation would have caused `total_supply` to exceed
    /// the `cap`.
    ExceededCap = 106,
    /// Indicates the supplied `cap` is not a valid cap value.
    InvalidCap = 107,
    /// Indicates the Cap was not set.
    CapNotSet = 108,
    /// Indicates the SAC address was not set.
    SACNotSet = 109,
    /// Indicates a SAC address different than expected.
    SACAddressMismatch = 110,
    /// Indicates a missing function parameter in the SAC contract context.
    SACMissingFnParam = 111,
    /// Indicates an invalid function parameter in the SAC contract context.
    SACInvalidFnParam = 112,
    /// The user is not allowed to perform this operation
    UserNotAllowed = 113,
    /// The user is blocked and cannot perform this operation
    UserBlocked = 114,
}

// ################## CONSTANTS ##################

const DAY_IN_LEDGERS: u32 = 17280;
pub const BALANCE_EXTEND_AMOUNT: u32 = 30 * DAY_IN_LEDGERS;
pub const BALANCE_TTL_THRESHOLD: u32 = BALANCE_EXTEND_AMOUNT - DAY_IN_LEDGERS;
pub const ALLOW_BLOCK_EXTEND_AMOUNT: u32 = 30 * DAY_IN_LEDGERS;
pub const ALLOW_BLOCK_TTL_THRESHOLD: u32 = ALLOW_BLOCK_EXTEND_AMOUNT - DAY_IN_LEDGERS;
pub const INSTANCE_EXTEND_AMOUNT: u32 = 7 * DAY_IN_LEDGERS;
pub const INSTANCE_TTL_THRESHOLD: u32 = INSTANCE_EXTEND_AMOUNT - DAY_IN_LEDGERS;

// ################## EVENTS ##################

/// Event emitted when tokens are transferred between addresses.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Transfer {
    #[topic]
    pub from: Address,
    #[topic]
    pub to: Address,
    pub amount: i64,
}

/// Emits an event indicating a transfer of tokens.
///
/// # Arguments
///
/// * `e` - Access to Soroban environment.
/// * `from` - The address holding the tokens.
/// * `to` - The address receiving the transferred tokens.
/// * `amount` - The amount of tokens to be transferred.
#[cfg(not(feature = "certora"))]
pub fn emit_transfer(e: &Env, from: &Address, to: &Address, amount: i64) {
    Transfer { from: from.clone(), to: to.clone(), amount }.publish(e);
}

/// Event emitted when an allowance is approved.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Approve {
    #[topic]
    pub owner: Address,
    #[topic]
    pub spender: Address,
    pub amount: i64,
    pub live_until_ledger: u32,
}

/// Emits an event indicating an allowance was set.
///
/// # Arguments
///
/// * `e` - Access to Soroban environment.
/// * `owner` - The address holding the tokens.
/// * `spender` - The address authorized to spend the tokens.
/// * `amount` - The amount of tokens made available to `spender`.
/// * `live_until_ledger` - The ledger number at which the allowance expires.
#[cfg(not(feature = "certora"))]
pub fn emit_approve(
    e: &Env,
    owner: &Address,
    spender: &Address,
    amount: i64,
    live_until_ledger: u32,
) {
    Approve { owner: owner.clone(), spender: spender.clone(), amount, live_until_ledger }
        .publish(e);
}

/// Event emitted when tokens are minted.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Mint {
    #[topic]
    pub to: Address,
    pub amount: i64,
}

/// Emits an event indicating a mint of tokens.
///
/// # Arguments
///
/// * `e` - Access to Soroban environment.
/// * `to` - The address receiving the new tokens.
/// * `amount` - The amount of tokens to mint.
#[cfg(not(feature = "certora"))]
pub fn emit_mint(e: &Env, to: &Address, amount: i64) {
    Mint { to: to.clone(), amount }.publish(e);
}
