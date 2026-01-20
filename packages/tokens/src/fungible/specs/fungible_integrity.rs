use cvlr::{clog, cvlr_assert, cvlr_assume, cvlr_satisfy, nondet::*};
use cvlr_soroban::nondet_address;
use cvlr_soroban_derive::rule;
use soroban_sdk::{Address, Env};

use crate::fungible::{Base, FungibleToken};

// property: P-XX. Fungible-Integrity.
// description: Fungible token functions change state as expected.
// status: violated

#[rule]
// transfer changes balances accordingly
// status: verified
// link: https://prover.certora.com/output/40748/db11471423cc4d998bc2d55ad1f320c8/?anonymousKey=c1ab4c1c996f93a56dd7fdf2b1f89e3ab4aaa957
pub fn transfer_integrity(e: Env) {
    let to = nondet_address();
    clog!(cvlr_soroban::Addr(&to));
    let from = nondet_address();
    clog!(cvlr_soroban::Addr(&from));
    let amount: i128 = nondet();
    clog!(amount);
    let balance_from_pre = Base::balance(&e, &from);
    clog!(balance_from_pre);
    let balance_to_pre = Base::balance(&e, &to);
    clog!(balance_to_pre);
    let total_supply_pre = Base::total_supply(&e);
    clog!(total_supply_pre);
    Base::transfer(&e, &from, &to, amount);
    let balance_from_post = Base::balance(&e, &from);
    clog!(balance_from_post);
    let balance_to_post = Base::balance(&e, &to);
    clog!(balance_to_post);
    let total_supply_post = Base::total_supply(&e);
    clog!(total_supply_post);
    cvlr_assert!(total_supply_post == total_supply_pre);
    if to != from {
        cvlr_assert!(balance_from_post == balance_from_pre - amount);
        cvlr_assert!(balance_to_post == balance_to_pre + amount);
    } else {
        cvlr_assert!(balance_to_post == balance_to_pre);
    }
}

#[rule]
// transfer_from does not change total supply
// status: verified
// link: https://prover.certora.com/output/40748/db11471423cc4d998bc2d55ad1f320c8/?anonymousKey=c1ab4c1c996f93a56dd7fdf2b1f89e3ab4aaa957
pub fn transfer_from_integrity_1(e: Env) {
    let spender = nondet_address();
    let from = nondet_address();
    let to = nondet_address();
    let amount: i128 = nondet();

    let total_supply_pre = Base::total_supply(&e);
    Base::transfer_from(&e, &spender, &from, &to, amount);
    let total_supply_post = Base::total_supply(&e);
    cvlr_assert!(total_supply_post == total_supply_pre);
}

#[rule]
// transfer_from changes the balance of from accordingly
// status: verified
// link: https://prover.certora.com/output/40748/db11471423cc4d998bc2d55ad1f320c8/?anonymousKey=c1ab4c1c996f93a56dd7fdf2b1f89e3ab4aaa957
pub fn transfer_from_integrity_2(e: Env) {
    let spender = nondet_address();
    let from = nondet_address();
    let to = nondet_address();
    let amount: i128 = nondet();

    let balance_from_pre = Base::balance(&e, &from);
    Base::transfer_from(&e, &spender, &from, &to, amount);
    let balance_from_post = Base::balance(&e, &from);

    if to != from {
        cvlr_assert!(balance_from_post == balance_from_pre - amount);
    } else {
        cvlr_assert!(balance_from_post == balance_from_pre);
    }
}

#[rule]
// transfer_from changes the balance of to accordingly
// status: verified
// link: https://prover.certora.com/output/40748/db11471423cc4d998bc2d55ad1f320c8/?anonymousKey=c1ab4c1c996f93a56dd7fdf2b1f89e3ab4aaa957
pub fn transfer_from_integrity_3(e: Env) {
    let spender = nondet_address();
    let from = nondet_address();
    let to = nondet_address();
    let amount: i128 = nondet();

    let balance_to_pre = Base::balance(&e, &to);
    Base::transfer_from(&e, &spender, &from, &to, amount);
    let balance_to_post = Base::balance(&e, &to);

    if to != from {
        cvlr_assert!(balance_to_post == balance_to_pre + amount);
    } else {
        cvlr_assert!(balance_to_post == balance_to_pre);
    }
}

#[rule]
// transfer_from changes allowance accordingly (bug: allowance expiry issue)
// status: violated
// link: https://prover.certora.com/output/40748/db11471423cc4d998bc2d55ad1f320c8/?anonymousKey=c1ab4c1c996f93a56dd7fdf2b1f89e3ab4aaa957
pub fn transfer_from_integrity_4(e: Env) {
    let spender = nondet_address();
    let from = nondet_address();
    let to = nondet_address();
    let amount: i128 = nondet();
    clog!(cvlr_soroban::Addr(&spender));
    clog!(cvlr_soroban::Addr(&from));
    clog!(cvlr_soroban::Addr(&to));
    clog!(amount);
    let allowance_pre = Base::allowance(&e, &from, &spender);
    clog!(allowance_pre);
    Base::transfer_from(&e, &spender, &from, &to, amount);
    let allowance_post = Base::allowance(&e, &from, &spender);
    clog!(allowance_post);
    cvlr_assert!(allowance_post == allowance_pre - amount); // allowance to yourself is treated the same way.
}

#[rule]
// approve changes allowance accordingly
// status: verified
// link: https://prover.certora.com/output/40748/db11471423cc4d998bc2d55ad1f320c8/?anonymousKey=c1ab4c1c996f93a56dd7fdf2b1f89e3ab4aaa957
pub fn approve_integrity(e: Env) {
    // note - the allowance and approve are all in the same env.
    let owner = nondet_address();
    clog!(cvlr_soroban::Addr(&owner));
    let spender = nondet_address();
    clog!(cvlr_soroban::Addr(&spender));
    let amount: i128 = nondet();
    clog!(amount);
    let live_until_ledger: u32 = nondet();
    clog!(live_until_ledger);
    let allowance_pre = Base::allowance(&e, &owner, &spender);
    clog!(allowance_pre);
    Base::approve(&e, &owner, &spender, amount, live_until_ledger);
    let allowance_post = Base::allowance(&e, &owner, &spender);
    clog!(allowance_post);
    cvlr_assert!(allowance_post == amount);
}
