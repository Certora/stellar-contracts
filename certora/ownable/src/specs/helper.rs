use soroban_sdk::{Env, Address};
use stellar_access::ownable::OwnableStorageKey;
use cvlr::clog;
/// Returns `Some(Address)` if a pending owner is set, or `None` if there is no pending ownership transfer.
///
/// # Arguments
///
/// * `e` - Access to the Soroban environment.
pub fn get_pending_owner(e: &Env) -> Option<Address> {
    let pending_owner = e.storage().temporary().get::<_, Address>(&OwnableStorageKey::PendingOwner);

    // clog!(pending_owner.as_cvlr());
    pending_owner
}

