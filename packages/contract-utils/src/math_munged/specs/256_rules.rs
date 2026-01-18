use cvlr::{clog, cvlr_assert, cvlr_assume, cvlr_satisfy, nondet::Nondet};
use cvlr_soroban_derive::rule;
use soroban_sdk::Env;

use crate::math_munged::{
    fixed_point::Rounding, i128_fixed_point::*, soroban_fixed_point::SorobanFixedPoint,
};

#[rule]
pub fn munged_i256_mul_div_floor_integrity_1(e: &Env) {
    let x = I256::nondet();
    clog!(x);
    let y = I256::nondet();
    clog!(y);
    let z = I256::nondet();
    clog!(z);
    let result = x.mul_div_floor(e, &y, &z);
    clog!(result);
}