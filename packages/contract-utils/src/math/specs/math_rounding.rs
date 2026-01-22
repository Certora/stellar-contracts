use cvlr::{clog, cvlr_assert, cvlr_assume, cvlr_satisfy, nondet::*};
use cvlr_soroban_derive::rule;
use soroban_sdk::Env;

use crate::math::math_64::i64_fixed_point::{div_ceil, div_floor};

#[rule]
// div_floor rounds correctly when the result is non-negative
// status: violation
// link: https://prover.certora.com/output/33158/14b5817d1bb04d45aa3abd1be1f84b36
pub fn div_floor_rounds_correct_when_result_nonneg(_e: Env) {
    let r = i64::nondet();
    
    let z = i64::nondet();
    
    cvlr_assume!((r > 0 && z > 0) || (r < 0 && z < 0));
    
    clog!(r);
    clog!(z);

    let result = div_floor(r, z);
    clog!(result);

    let expected = r / z;
    clog!(expected);

    cvlr_assume!(result.is_some());
    
    let res = result.unwrap();

    clog!(res);
    cvlr_assert!(res == expected);
}

#[rule]
// div_floor rounds correctly when the result is negative
// status: verified
// link: https://prover.certora.com/output/33158/14b5817d1bb04d45aa3abd1be1f84b36
pub fn div_floor_rounds_correct_when_result_neg(_e: Env) {
    let r = i64::nondet();
    let z = i64::nondet();

    cvlr_assume!((r > 0 && z < 0) || (r < 0 && z > 0));
    cvlr_assume!(r % z != 0);

    clog!(r);
    clog!(z);

    let result = div_floor(r, z);
    clog!(result);

    cvlr_assume!(result.is_some());

    let expected = (r / z) - 1;
    clog!(expected);

    cvlr_assert!(result.unwrap() == expected);
}

#[rule]
// div_ceil rounds correctly when the result is non-positive
// status: verified
// link: https://prover.certora.com/output/33158/14b5817d1bb04d45aa3abd1be1f84b36
pub fn div_ceil_rounds_correct_when_result_nonpos(_e: Env) {
    let r = i64::nondet();
    let z = i64::nondet();

    cvlr_assume!((r > 0 && z < 0) || (r < 0 && z > 0));

    clog!(r);
    clog!(z);

    let result = div_ceil(r, z);
    clog!(result);

    cvlr_assume!(result.is_some());

    let expected = r / z;

    clog!(expected);

    let res = result.unwrap();
    clog!(res);

    cvlr_assert!(res == expected);
}

#[rule]
// div_ceil rounds correctly when the result is positive
// status: violation
// link: https://prover.certora.com/output/33158/14b5817d1bb04d45aa3abd1be1f84b36
#[rule]
pub fn div_ceil_rounds_correct_when_result_pos(_e: Env) {
    let r = i64::nondet();
    let z = i64::nondet();

    cvlr_assume!((r > 0 && z > 0) || (r < 0 && z < 0));
    cvlr_assume!(r % z != 0);

    clog!(r);
    clog!(z);

    let result = div_ceil(r, z);
    clog!(result);

    cvlr_assume!(result.is_some());

    let expected = (r / z) + 1;
    clog!(expected);

    cvlr_assert!(result.unwrap() == expected);
}