use cvlr::{clog, cvlr_assert, cvlr_assume, cvlr_satisfy, nondet::*};
use cvlr_soroban_derive::rule;
use soroban_sdk::Env;

use crate::math::math_64::i64_fixed_point::{div_ceil, div_floor};

// property: P-XX. Math Rounding.
// description: muldiv functions round correctly.
// status: violated

#[rule]
// div_floor rounds correctly 1
// status:
pub fn div_floor_rounds_correct_1(_e: Env) {
    let r = i64::nondet();
    let z = i64::nondet();

    cvlr_assume!((r > 0 && z > 0) || (r < 0 && z < 0));
    cvlr_assume!(!(r == i64::MIN && z == -1));

    clog!(r);
    clog!(z);

    let result = div_floor(r, z);
    clog!(result);

    let expected = r / z;
    clog!(expected);

    cvlr_assert!(result == expected);
}

#[rule]
// div_floor rounds correctly 2
// status:
pub fn div_floor_rounds_correct_2(_e: Env) {
    let r = i64::nondet();
    let z = i64::nondet();

    cvlr_assume!((r > 0 && z < 0) || (r < 0 && z > 0));
    cvlr_assume!(r % z != 0);

    clog!(r);
    clog!(z);

    let result = div_floor(r, z);
    clog!(result);

    let expected = (r / z) - 1;
    clog!(expected);

    cvlr_assert!(result == expected);
}

#[rule]
// div_ceil rounds correctly 1
// status: 
pub fn div_ceil_rounds_correct_1(_e: Env) {
    let r = i64::nondet();
    let z = i64::nondet();

    cvlr_assume!((r > 0 && z < 0) || (r < 0 && z > 0));

    clog!(r);
    clog!(z);

    let result = div_ceil(r, z);
    clog!(result);

    let expected = r / z;

    clog!(expected);
    cvlr_assert!(result == expected);
}

#[rule]
// div_ceil rounds correctly 2
// status: 
pub fn div_ceil_rounds_correct_2(_e: Env) {
    let r = i64::nondet();
    let z = i64::nondet();

    cvlr_assume!((r > 0 && z > 0) || (r < 0 && z < 0));
    cvlr_assume!(!(r == i64::MIN && z == -1));
    cvlr_assume!(r % z != 0);

    clog!(r);
    clog!(z);

    let result = div_ceil(r, z);
    clog!(result);

    let expected = (r / z) + 1;
    clog!(expected);

    cvlr_assert!(result == expected);
}
