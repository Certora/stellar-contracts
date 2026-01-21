use soroban_sdk::{contracttype, Env};

use crate::math::math_64::soroban_fixed_point::SorobanFixedPoint;

// For formal verification purposes

#[contracttype]
pub enum Rounding {
    Floor, // Toward negative infinity
    Ceil,  // Toward positive infinity
}

/**
 * Calculates x * y / denominator with full precision, following the
 * selected rounding direction. Throws if result overflows a i64 or
 * denominator is zero (handles phantom overflow).
 */
pub fn muldiv(e: &Env, x: i64, y: i64, denominator: i64, rounding: Rounding) -> i64 {
    match rounding {
        Rounding::Floor => x.fixed_mul_floor(e, &y, &denominator),
        Rounding::Ceil => x.fixed_mul_ceil(e, &y, &denominator),
    }
}
