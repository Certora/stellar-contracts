use cvlr::{clog, log::CvlrLog, prelude::*};
use cvlr_soroban::nondet_address;
use cvlr_soroban_derive::rule;
use soroban_sdk::Env;
use stellar_access::ownable::Ownable;

use crate::{
    ownable_contract::FVHarnessOwnableContract,
    specs::{cvlr::CvlrProp, ownable_invariant2::OwnableInvariant},
};

pub struct Inputs<'a> {
    pub e: &'a Env,
}

#[derive(Default)]
pub struct BaseEnv {}

macro_rules! impl_base {
    ($name: ident, $e: ident, $body: expr) => {
        #[inline(always)]
        pub fn $name<C>(e: &Env)
        where
            C: CvlrProp + CvlrLog + for<'a> From<(Inputs<'a>, BaseEnv)>,
        {
            let pre: C = (Inputs { e }, BaseEnv::default()).into();
            pre.assume_pre();

            let env = {
                let $e = e;
                $body
            };

            let post: C = (Inputs { e }, env).into();
            clog!(pre, post);
            post.check_post(&pre);
        }
    };
}

impl_base! {
    base_transfer_ownership,
    e,
    {
        let new_owner = nondet_address();
        let live_until_ledger: u32 = nondet();
        FVHarnessOwnableContract::transfer_ownership(&e, new_owner, live_until_ledger);
        BaseEnv::default()
    }
}

impl_base! {
    base_accept_ownership,
    e,
    {
        FVHarnessOwnableContract::accept_ownership(&e);
        BaseEnv::default()
    }
}

impl_base! {
    base_renounce_ownership,
    e,
    {
        FVHarnessOwnableContract::renounce_ownership(&e);
        BaseEnv::default()
    }
}

impl_base! {
    base_owner_restricted_function,
    e,
    {
        FVHarnessOwnableContract::owner_restricted_function(&e);
        BaseEnv::default()
    }
}