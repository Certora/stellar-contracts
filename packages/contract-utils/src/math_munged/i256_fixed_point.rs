/*
MIT License

Copyright (c) 2023 Script3 Ltd. and contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/
// Based on the Soroban fixed-point mathematics library
// Original implementation: https://github.com/script3/soroban-fixed-point-math

use soroban_sdk::{panic_with_error, Env};

use crate::math_munged::soroban_fixed_point::{SorobanFixedPoint, SorobanFixedPointError};

impl SorobanFixedPoint for i128 {
    fn fixed_mul_floor(&self, env: &Env, y: &i128, denominator: &i128) -> i128 {
        mul_div_floor(env, self, y, denominator)
    }

    fn fixed_mul_ceil(&self, env: &Env, y: &i128, denominator: &i128) -> i128 {
        mul_div_ceil(env, self, y, denominator)
    }
}

/// Performs floor(x * y / z)
pub(crate) fn mul_div_floor(env: &Env, x: &i128, y: &i128, z: &i128) -> i128 {
    let r = x * y;

    if *z == 0 {
        panic_with_error!(env, SorobanFixedPointError::ZeroDenominator);
    }

    if r < 0 || (r > 0 && *z < 0) {
        // ceil is taken by default for a negative result
        let remainder = r.rem_euclid(*z);
        r / z - if remainder > 0 { 1 } else { 0 }
    } else {
        // floor is taken by default for a positive or zero result
        r / z
    }
}

/// Performs ceil(x * y / z)
pub(crate) fn mul_div_ceil(env: &Env, x: &i128, y: &i128, z: &i128) -> i128 {
    let r = x * y;

    if *z == 0 {
        panic_with_error!(env, SorobanFixedPointError::ZeroDenominator);
    }

    if *z < 0 || r <= 0 {
        // ceil is taken by default for a negative or zero result
        r / z
    } else {
        // floor is taken by default for a positive result
        let remainder = r.rem_euclid(*z);
        r / z + if remainder > 0 { 1 } else { 0 }
    }
}
