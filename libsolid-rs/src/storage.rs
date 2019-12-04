use crate::Client;
use failure::Fallible;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::collections::HashMap;

/// Trait which defines functionality for storing and restoring a `Client`
pub trait Storage<C, S>: Serialize + DeserializeOwned
where
    C: Client<S>,
    S: Serialize + DeserializeOwned,
{
    fn store_state(&mut self, client: C) -> Fallible<()>;
    fn restore_state(&mut self, provider_id: String) -> Fallible<S>;

    fn write_storage(&self, w: Box<dyn std::io::Write>) -> Fallible<()> {
        serde_json::to_writer_pretty(w, &self).map_err(failure::Error::from)
    }

    fn read_storage(r: Box<dyn std::io::Read>) -> Fallible<Self> {
        serde_json::from_reader(r).map_err(failure::Error::from)
    }
}

impl<C: Client<S>, S: Serialize + DeserializeOwned> Storage<C, S> for HashMap<String, Vec<u8>> {
    fn store_state(&mut self, client: C) -> Fallible<()> {
        self.insert(
            client.provider_id().to_string(),
            serde_json::to_vec(client.state())?,
        );

        Ok(())
    }

    fn restore_state(&mut self, provider_id: String) -> Fallible<S> {
        let serialized = self.remove(&provider_id).ok_or_else(|| {
            failure::err_msg(format!("no state stored for provider {}", provider_id))
        })?;

        serde_json::from_slice(&serialized).map_err(failure::Error::from)
    }
}
