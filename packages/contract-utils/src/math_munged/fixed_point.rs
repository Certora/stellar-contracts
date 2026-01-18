use soroban_sdk::{contracttype, Env};

use crate::math_munged::soroban_fixed_point::SorobanFixedPoint;

#[contracttype]
pub enum Rounding {
    Floor, // Toward negative infinity
    Ceil,  // Toward positive infinity
}

/**
 * Calculates x * y / denominator with full precision, following the
 * selected rounding direction. Throws if result overflows a i32 or
 * denominator is zero (handles phantom overflow).
 */
pub fn muldiv(e: &Env, x: i32, y: i32, denominator: i32, rounding: Rounding) -> i32 {
    match rounding {
        Rounding::Floor => x.fixed_mul_floor(e, &y, &denominator),
        Rounding::Ceil => x.fixed_mul_ceil(e, &y, &denominator),
    }
}
