use cvlr::{cvlr_assert, cvlr_assume, log::CvlrLog};
use soroban_sdk::{Address, Env};
use stellar_access::ownable::{Ownable, OwnableStorageKey};

use super::base::*;
use crate::{
    cvlr_inv, impl_cvlr_rule_for_bases,
    ownable_contract::FVHarnessOwnableContract,
    specs::{
        base::{BaseEnv, Inputs},
        cvlr::CvlrProp,
    },
};

pub struct SanityInvariant {
    pub owner: Option<Address>,
    pub pending_owner: Option<Address>,
}

impl CvlrProp for SanityInvariant {
    fn assume_pre(&self) {
        
    }
    
    fn check_post(&self, _old: &Self) {
        cvlr_assert!(false);
    }

}

impl_cvlr_rule_for_bases! {
    SanityInvariant,
    sanity_invariant_transfer_ownership => base_transfer_ownership,
    sanity_invariant_accept_ownership => base_accept_ownership,
    sanity_invariant_restricted_function => base_owner_restricted_function,
    sanity_invariant_renounce_ownership => base_renounce_ownership,
}

// trait implementation don't look here
impl CvlrLog for SanityInvariant {
    #[inline(always)]
    fn log(&self, tag: &str, logger: &mut cvlr::log::CvlrLogger) {
        logger.log_scope_start(tag);
        match self.owner.as_ref() {
            Some(addr) => cvlr::log::cvlr_log_with("owner", &cvlr_soroban::Addr(addr), logger),
            None => logger.log_str("owner", "None"),
        }
        match self.pending_owner.as_ref() {
            Some(addr) =>
                cvlr::log::cvlr_log_with("pending_owner", &cvlr_soroban::Addr(addr), logger),
            None => logger.log_str("pending_owner", "None"),
        }
        logger.log_scope_end(tag);
    }
}

impl<'a> From<(Inputs<'a>, BaseEnv)> for SanityInvariant {
    fn from(input: (Inputs, BaseEnv)) -> Self {
        let (i, _e) = input;
        Self {
            owner: FVHarnessOwnableContract::get_owner(i.e),
            pending_owner: i
                .e
                .storage()
                .temporary()
                .get::<_, Address>(&OwnableStorageKey::PendingOwner),
        }
    }
}
