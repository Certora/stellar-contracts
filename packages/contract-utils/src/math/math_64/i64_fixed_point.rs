use soroban_sdk::{panic_with_error, Env};

use crate::math::math_64::soroban_fixed_point::{SorobanFixedPoint, SorobanFixedPointError};

// For formal verification purposes

// NOTE: even though the rest of the reruns of the FV jobs are done on
// commit `a1163e9dea184f9728318b4defb20dc349914387`,
// this code is taken from `main` because the above commit
// only had the checked versions of the code which is not what we verified
// initially. These non-checked versions seem to have been added later.
// checked versions are also a bit harder for FV due to the complex bytecode
// that they generate. We also replace rem_euclid with % which in this case
// should be equivalent.

/// Performs floor(r / z)
pub fn div_floor(r: i64, z: i64) -> i64 {
    if (r < 0 && z > 0) || (r > 0 && z < 0) {
        // ceiling is taken by default for a negative result
        (r / z) - (if r % z != 0 { 1 } else { 0 })
    } else {
        // floor taken by default for a positive or zero result
        r / z
    }
}

/// Performs ceil(r / z)
pub fn div_ceil(r: i64, z: i64) -> i64 {
    if (r <= 0 && z > 0) || (r >= 0 && z < 0) {
        // ceiling is taken by default for a negative or zero result
        r / z
    } else {
        // floor taken by default for a positive result
        r / z + (if r % z != 0 { 1 } else { 0 })
    }
}

impl SorobanFixedPoint for i64 {
    fn fixed_mul_floor(&self, env: &Env, y: &i64, denominator: &i64) -> i64 {
        scaled_mul_div_floor(self, env, y, denominator)
    }

    fn fixed_mul_ceil(&self, env: &Env, y: &i64, denominator: &i64) -> i64 {
        scaled_mul_div_ceil(self, env, y, denominator)
    }
}

fn mul_div_floor_i128(env: &Env, x: i128, y: i128, z: i128) -> i128 {
    if z == 0 {
        panic_with_error!(env, SorobanFixedPointError::ZeroDenominator);
    }

    let r = x * y;
    if (r < 0 && z > 0) || (r > 0 && z < 0) {
        (r / z) - (if r % z != 0 { 1 } else { 0 })
    } else {
        r / z
    }
}

fn mul_div_ceil_i128(env: &Env, x: i128, y: i128, z: i128) -> i128 {
    if z == 0 {
        panic_with_error!(env, SorobanFixedPointError::ZeroDenominator);
    }

    let r = x * y;
    if (r <= 0 && z > 0) || (r >= 0 && z < 0) {
        r / z
    } else {
        r / z + (if r % z != 0 { 1 } else { 0 })
    }
}

pub(crate) fn scaled_mul_div_floor(x: &i64, env: &Env, y: &i64, z: &i64) -> i64 {
    match x.checked_mul(*y) {
        Some(r) => {
            if *z == 0 {
                panic_with_error!(env, SorobanFixedPointError::ZeroDenominator);
            }
            if r == i64::MIN && *z == -1 {
                panic_with_error!(env, SorobanFixedPointError::ResultOverflow);
            }
            div_floor(r, *z)
        }
        None => {
            let res = mul_div_floor_i128(env, *x as i128, *y as i128, *z as i128);
            i64::try_from(res)
                .ok()
                .unwrap_or_else(|| panic_with_error!(env, SorobanFixedPointError::ResultOverflow))
        }
    }
}

pub(crate) fn scaled_mul_div_ceil(x: &i64, env: &Env, y: &i64, z: &i64) -> i64 {
    match x.checked_mul(*y) {
        Some(r) => {
            if *z == 0 {
                panic_with_error!(env, SorobanFixedPointError::ZeroDenominator);
            }
            if r == i64::MIN && *z == -1 {
                panic_with_error!(env, SorobanFixedPointError::ResultOverflow);
            }
            div_ceil(r, *z)
        }
        None => {
            let res = mul_div_ceil_i128(env, *x as i128, *y as i128, *z as i128);
            i64::try_from(res)
                .ok()
                .unwrap_or_else(|| panic_with_error!(env, SorobanFixedPointError::ResultOverflow))
        }
    }
}
