use cvlr::{clog, cvlr_assert, cvlr_assume, cvlr_satisfy, nondet::Nondet};
use cvlr_soroban_derive::rule;
use soroban_sdk::Env;

use crate::math_munged::{
    fixed_point::Rounding, i128_fixed_point::*, soroban_fixed_point::SorobanFixedPoint,
};

#[rule]
// fixed_mul_floor returns at most muldiv
// status: 
pub fn munged_fixed_mul_floor_integrity_1(e: &Env) {
    let x = i32::nondet();
    clog!(x);
    let y = i32::nondet();
    clog!(y);
    let z = i32::nondet();
    clog!(z);
    let result = x.fixed_mul_floor(e, &y, &z);
    clog!(result);
    let expected_result = x * y / z;
    clog!(expected_result);
    cvlr_assert!(result <= expected_result);
}

#[rule]
// sanity
// status: 
pub fn munged_fixed_mul_floor_integrity_sanity_1(e: &Env) {
    let x = i32::nondet();
    clog!(x);
    let y = i32::nondet();
    clog!(y);
    let z = i32::nondet();
    clog!(z);
    let result = x.fixed_mul_floor(e, &y, &z);
    clog!(result);
    let expected_result = x * y / z;
    clog!(expected_result);
    cvlr_satisfy!(true);
    // let max_rounding_error = 1;
    // clog!(max_rounding_error);
    // let lower_bound = expected_result.checked_sub(max_rounding_error).unwrap();
    // cvlr_assert!(result >= lower_bound);
}

#[rule]
// fixed_mul_floor returns at least muldiv - 1
// status: 
pub fn munged_fixed_mul_floor_integrity_2(e: &Env) {
    let x = i32::nondet();
    clog!(x);
    let y = i32::nondet();
    clog!(y);
    let z = i32::nondet();
    clog!(z);
    let result = x.fixed_mul_floor(e, &y, &z);
    clog!(result);
    let expected_result = x * y / z;
    clog!(expected_result);
    let lower_bound = expected_result.checked_sub(1).unwrap();
    clog!(lower_bound);
    cvlr_assert!(result >= lower_bound);
}

#[rule]
// sanity
// status: 
pub fn munged_fixed_mul_floor_integrity_sanity_2(e: &Env) {
    let x = i32::nondet();
    clog!(x);
    let y = i32::nondet();
    clog!(y);
    let z = i32::nondet();
    clog!(z);
    let result = x.fixed_mul_floor(e, &y, &z);
    clog!(result);
    let expected_result = x * y / z;
    clog!(expected_result);
    let lower_bound = expected_result.checked_sub(1).unwrap();
    clog!(lower_bound);
    cvlr_satisfy!(true);
}

#[rule]
// fixed_mul_ceil returns at least muldiv
// status: 
pub fn munged_fixed_mul_ceil_integrity_1(e: &Env) {
    let x = i32::nondet();
    clog!(x);
    let y = i32::nondet();
    clog!(y);
    let z = i32::nondet();
    clog!(z);
    let result = x.fixed_mul_ceil(e, &y, &z);
    clog!(result);
    let expected_result = x * y / z;
    clog!(expected_result);
    cvlr_assert!(result >= expected_result);
}

#[rule]
// sanity
// status: 
pub fn munged_fixed_mul_ceil_integrity_sanity_1(e: &Env) {
    let x = i32::nondet();
    clog!(x);
    let y = i32::nondet();
    clog!(y);
    let z = i32::nondet();
    clog!(z);
    let result = x.fixed_mul_ceil(e, &y, &z);
    clog!(result);
    let expected_result = x * y / z;
    clog!(expected_result);
    cvlr_satisfy!(true);
}

#[rule]
// fixed_mul_ceil returns at most muldiv + 1
// status: 
pub fn munged_fixed_mul_ceil_integrity_2(e: &Env) {
    let x = i32::nondet();
    clog!(x);
    let y = i32::nondet();
    clog!(y);
    let z = i32::nondet();
    clog!(z);
    let result = x.fixed_mul_ceil(e, &y, &z);
    clog!(result);
    let expected_result = x * y / z;
    clog!(expected_result);
    let upper_bound = expected_result.checked_add(1).unwrap();
    clog!(upper_bound);
    cvlr_assert!(result <= upper_bound);
}

#[rule]
// sanity
// status: 
pub fn munged_fixed_mul_ceil_integrity_sanity_2(e: &Env) {
    let x = i32::nondet();
    clog!(x);
    let y = i32::nondet();
    clog!(y);
    let z = i32::nondet();
    clog!(z);
    let result = x.fixed_mul_ceil(e, &y, &z);
    clog!(result);
    let expected_result = x * y / z;
    clog!(expected_result);
    let upper_bound = expected_result.checked_add(1).unwrap();
    clog!(upper_bound);
    cvlr_satisfy!(true);
}

#[rule]
// fixed_mul_floor panics if the denominator is 0
// status: 
pub fn munged_fixed_mul_floor_panics_if_zero_denominator(e: &Env) {
    let x = i32::nondet();
    clog!(x);
    let y = i32::nondet();
    clog!(y);
    let z = i32::nondet();
    cvlr_assume!(z == 0);
    let _ = x.fixed_mul_floor(e, &y, &z);
    cvlr_assert!(false);
}

#[rule]
// fixed_mul_ceil panics if the denominator is 0
// status: 
pub fn munged_fixed_mul_ceil_panics_if_zero_denominator(e: &Env) {
    let x = i32::nondet();
    clog!(x);
    let y = i32::nondet();
    clog!(y);
    let z = i32::nondet();
    cvlr_assume!(z == 0);
    let _ = x.fixed_mul_ceil(e, &y, &z);
    cvlr_assert!(false);
}

use crate::math_munged::i256_fixed_point::mul_div_floor;

pub fn mul_div_floor_256_integrity_1(e: &Env) {
    let x = i128::nondet();
    clog!(x);
    let y = i128::nondet();
    clog!(y);
    let z = i128::nondet();
    clog!(z);
    let result = mul_div_floor(e, &x, &y, &z);
    clog!(result);
    let expected_result = x * y / z;
    clog!(expected_result);
    cvlr_assert!(result <= expected_result);
}