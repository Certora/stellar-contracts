use cvlr::{clog, cvlr_assert, cvlr_assume, cvlr_satisfy, nondet::Nondet};
use cvlr_soroban_derive::rule;
use soroban_sdk::Env;

use crate::math_munged::{
    fixed_point::Rounding, i128_fixed_point::*, soroban_fixed_point::SorobanFixedPoint,
};

#[rule]
// fixed_mul_floor rounds down
// status: 
pub fn munged_fixed_mul_floor_rounds_down(e: &Env) {
    let x = i32::nondet();
    clog!(x);
    cvlr_assume!(x <= i32::MAX as i32 && x >= i32::MIN as i32);
    let y = i32::nondet();
    clog!(y);
    cvlr_assume!(y <= i32::MAX as i32 && y >= i32::MIN as i32);
    let z = i32::nondet();
    clog!(z);
    cvlr_assume!(z <= i32::MAX as i32 && z >= i32::MIN as i32);
    let result = x.fixed_mul_floor(e, &y, &z);
    clog!(result);
    let result_rounded_towards_zero = x * y / z;
    clog!(result_rounded_towards_zero);
    let result_rounded_towards_zero_mul_z = result_rounded_towards_zero * z;
    clog!(result_rounded_towards_zero_mul_z);
    let x_times_y = x * y;
    clog!(x_times_y);
    let result_rounded_down: i32;
    if (result_rounded_towards_zero_mul_z > x * y && z > 0) ||
       (result_rounded_towards_zero_mul_z < x * y && z < 0) 
    {
        result_rounded_down = result_rounded_towards_zero - 1;
    } else {
        result_rounded_down = result_rounded_towards_zero;
    }
    clog!(result_rounded_down);
    cvlr_assert!(result_rounded_down == result);
}

#[rule]
// fixed_mul_ceil rounds up
// status: 
pub fn munged_fixed_mul_ceil_rounds_up(e: &Env) {
    let x = i32::nondet();
    clog!(x);
    let y = i32::nondet();
    clog!(y);
    let z = i32::nondet();
    clog!(z);
    let result = x.fixed_mul_ceil(e, &y, &z);
    clog!(result);
    let result_rounded_towards_zero = x * y / z; // rounds towards zero.
    clog!(result_rounded_towards_zero);
    let result_rounded_towards_zero_mul_z = result_rounded_towards_zero * z;
    clog!(result_rounded_towards_zero_mul_z);
    let result_rounded_up = 0;
    if (result_rounded_towards_zero_mul_z < x * y && z > 0) ||
       (result_rounded_towards_zero_mul_z > x * y && z < 0) 
    {
        let result_rounded_up = result_rounded_towards_zero + 1;
    }
    else {
        let result_rounded_up = result_rounded_towards_zero;
    }
    clog!(result_rounded_up);
    cvlr_assert!(result == result_rounded_up);
}