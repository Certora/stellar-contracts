use cvlr::{cvlr_assert, cvlr_satisfy, nondet::*};
use cvlr_soroban::nondet_address;
use cvlr_soroban_derive::rule;
use soroban_sdk::Env;

use crate::fungible::{specs::capped_contract::CappedTokenContract, FungibleToken};

// property: P-XX. Capped-Integrity.
// description: Capped mint increases the balance and total supply by the amount minted and does not exceed the cap.
// status: verified

#[rule]
// after mint the account's balance and total supply increase by amount
// status: verified
// link: https://prover.certora.com/output/40748/77feac7184e54260ab75f292702b8634/?anonymousKey=bcfb9359cc1c6e8cbafba8abc9ec0f50ee80a84c
pub fn mint_integrity(e: Env) {
    let account = nondet_address();
    let amount = nondet();
    let balance_pre = CappedTokenContract::balance(&e, account.clone());
    let total_supply_pre = CappedTokenContract::total_supply(&e);
    CappedTokenContract::mint(&e, account.clone(), amount);
    let balance_post = CappedTokenContract::balance(&e, account);
    let total_supply_post = CappedTokenContract::total_supply(&e);
    cvlr_assert!(balance_post == balance_pre + amount);
    cvlr_assert!(total_supply_post == total_supply_pre + amount);
}

#[rule]
// after a mint the total supply doesn't surpass the cap
// status: verified
// link: https://prover.certora.com/output/40748/77feac7184e54260ab75f292702b8634/?anonymousKey=bcfb9359cc1c6e8cbafba8abc9ec0f50ee80a84c
pub fn mint_preserves_cap(e: Env) {
    let amount = nondet();
    let account = nondet_address();
    CappedTokenContract::mint(&e, account.clone(), amount);
    let total_supply = CappedTokenContract::total_supply(&e);
    let cap = CappedTokenContract::get_cap(&e);
    cvlr_assert!(total_supply <= cap);
}

#[rule]
// after constructor the cap is set
// status: verified
// link: https://prover.certora.com/output/40748/77feac7184e54260ab75f292702b8634/?anonymousKey=bcfb9359cc1c6e8cbafba8abc9ec0f50ee80a84c
pub fn constructor_integrity(e: Env) {
    let cap = nondet();
    CappedTokenContract::__constructor(&e, cap);
    let cap_post = CappedTokenContract::get_cap(&e);
    cvlr_assert!(cap_post == cap);
    cvlr_assert!(cap >= 0);
}
