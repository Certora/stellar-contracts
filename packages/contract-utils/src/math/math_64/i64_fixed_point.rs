use soroban_sdk::{panic_with_error, Env};

// For formal verification purposes

// NOTE: even though the rest of the reruns of the FV jobs are done on 
// commit `a1163e9dea184f9728318b4defb20dc349914387`,
// this code is taken from `main` because the above commit
// only had the checked versions of the code which is not what we verified initially.
// These non-checked versions seem to have been added later.
// checked versions are also a bit harder for FV due to the complex bytecode that they generate.
// We also replace rem_euclid with % which in this case should be equivalent.

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