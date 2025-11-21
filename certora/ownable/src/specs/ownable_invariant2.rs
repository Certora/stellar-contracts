use super::base::*;
use cvlr::{cvlr_assert, cvlr_assume, log::CvlrLog};
use soroban_sdk::{Address, Env};
use stellar_access::ownable::Ownable;

use crate::{
    cvlr_inv, impl_cvlr_rule_for_bases, ownable_contract::FVHarnessOwnableContract, specs::{
        base::{BaseEnv, Inputs},
        cvlr::CvlrProp,
    }
};

pub struct OwnableInvariant {
    pub owner: Option<Address>,
}

impl CvlrProp for OwnableInvariant {
    cvlr_inv! {s -> s.owner.is_some()}
}

impl_cvlr_rule_for_bases! {
    OwnableInvariant,
    ownable_invariant_transfer_ownership => base_transfer_ownership,
    ownable_invariant_accept_ownership => base_accept_ownership,
    ownable_invariant_restricted_function => base_owner_restricted_function
}

// trait implementation don't look here
impl CvlrLog for OwnableInvariant {
    #[inline(always)]
    fn log(&self, tag: &str, logger: &mut cvlr::log::CvlrLogger) {
        logger.log_scope_start(tag);
        match self.owner.as_ref() {
            Some(addr) => cvlr::log::cvlr_log_with("owner", &cvlr_soroban::Addr(addr), logger),
            None => logger.log_str("owner", "None"),
        }
        logger.log_scope_end(tag);
    }
}

impl<'a> From<(Inputs<'a>, BaseEnv)> for OwnableInvariant {
    fn from(input: (Inputs, BaseEnv)) -> Self {
        let (i, _e) = input;
        Self { owner: FVHarnessOwnableContract::get_owner(i.e) }
    }
}
