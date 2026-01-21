use cvlr::{clog, cvlr_assert, cvlr_assume, cvlr_satisfy, nondet::*};
use cvlr_soroban::{nondet_address, nondet_bytes, nondet_bytes_n, nondet_string};
use cvlr_soroban_derive::rule;
use soroban_sdk::{Address, Env, Vec};
use crate::rwa::utils::token_binder::{bind_token, bind_tokens, is_token_bound, linked_tokens, unbind_token};
use crate::rwa::specs::helpers::nondet::nondet_vec_address;
use crate::rwa::utils::token_binder::storage::linked_token_count;
use crate::rwa::specs::helpers::clogs::clog_vec_addresses;

// P-XX. Token Binder-Integrity.
// description: Token Binder functions change state as expected.
// status: verified

#[rule]
// after bind_token the token is bound
// status: verified
// link: https://prover.certora.com/output/40748/182e4f56434c43fa8a2ea60f37b11426/?anonymousKey=9a1525202168947199b27f0b2e5194b63317d068
pub fn bind_token_integrity_1(e: Env) {
    let token = nondet_address();
    clog!(cvlr_soroban::Addr(&token));
    bind_token(&e, &token);
    let is_token_bound = is_token_bound(&e, &token);
    clog!(is_token_bound);
    cvlr_assert!(is_token_bound);
}

#[rule]
// after bind_token the token count is incremented
// status: verified
// link: https://prover.certora.com/output/40748/182e4f56434c43fa8a2ea60f37b11426/?anonymousKey=9a1525202168947199b27f0b2e5194b63317d068
pub fn bind_token_integrity_2(e: Env) {
    let token = nondet_address();
    clog!(cvlr_soroban::Addr(&token));  
    let token_count_pre = linked_token_count(&e);
    clog!(token_count_pre);
    bind_token(&e, &token);
    let token_count_post = linked_token_count(&e);
    clog!(token_count_post);
    cvlr_assert!(token_count_post == token_count_pre + 1);
}

#[rule]
// after bind_tokens any token is bounded
// status: verified
// link: https://prover.certora.com/output/40748/182e4f56434c43fa8a2ea60f37b11426/?anonymousKey=9a1525202168947199b27f0b2e5194b63317d068
pub fn bind_tokens_integrity_1(e: Env) {
    let tokens: Vec<Address> = nondet_vec_address();
    clog_vec_addresses(&tokens);
    let token: Address = nondet_address();
    clog!(cvlr_soroban::Addr(&token));
    let token_in_tokens = tokens.contains(&token);
    clog!(token_in_tokens);
    cvlr_assume!(token_in_tokens);
    bind_tokens(&e, &tokens);
    let is_token_bound = is_token_bound(&e, &token);
    clog!(is_token_bound);
    cvlr_assert!(is_token_bound);
}


#[rule]
// after bind_tokens the token count is incremented
// status: verified
// link: https://prover.certora.com/output/40748/182e4f56434c43fa8a2ea60f37b11426/?anonymousKey=9a1525202168947199b27f0b2e5194b63317d068
pub fn bind_tokens_integrity_2(e: Env) {
    let tokens = nondet_vec_address();
    clog_vec_addresses(&tokens);
    let tokens_length = tokens.len();
    clog!(tokens_length);
    let token_count_pre = linked_token_count(&e);
    clog!(token_count_pre);
    bind_tokens(&e, &tokens);
    let token_count_post = linked_token_count(&e);
    clog!(token_count_post);
    cvlr_assert!(token_count_post == token_count_pre + tokens_length);
}
