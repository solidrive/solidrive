pub mod auth;
pub mod storage;

use failure::Fallible;
use serde::{de::DeserializeOwned, Serialize};

pub type ProviderID = String;

pub trait Client<S>
where
    S: Serialize + DeserializeOwned,
{
    /// Get the Client's ProviderId.
    fn provider_id(&self) -> &ProviderID;

    /// Get the Client's state.
    fn state(&self) -> &S;

    /// Fetch data from the given URL and try to parse it into type D
    fn fetch<D>(_url: String) -> Fallible<D> {
        unimplemented!()
    }
}
