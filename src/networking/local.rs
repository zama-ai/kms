use super::*;
use dashmap::DashMap;
use std::sync::Arc;

/// A simple implementation of networking for local execution.
///
/// This implementation is intended for local development/testing purposes
/// only. It simply stores all values in a hashmap without any actual networking.
#[derive(Default)]
pub struct LocalNetworking {
    store: DashMap<String, Arc<async_cell::sync::AsyncCell<Value>>>,
}

#[async_trait]
impl Networking for LocalNetworking {
    async fn send(
        &self,
        val: Value,
        _receiver: &Identity,
        rendezvous_key: &RendezvousKey,
        session_id: &SessionId,
    ) -> anyhow::Result<()> {
        tracing::debug!("Async sending; rdv:'{rendezvous_key}' sid:{session_id}");
        let key = format!("{session_id}/{rendezvous_key}");
        self.store
            .entry(key)
            .or_insert_with(async_cell::sync::AsyncCell::shared)
            .value()
            .set(val);
        Ok(())
    }

    async fn receive(
        &self,
        _sender: &Identity,
        rendezvous_key: &RendezvousKey,
        session_id: &SessionId,
    ) -> anyhow::Result<Value> {
        tracing::debug!("Async receiving; rdv:'{rendezvous_key}', sid:{session_id}");
        let key = format!("{session_id}/{rendezvous_key}");
        let cell = self
            .store
            .entry(key)
            .or_insert_with(async_cell::sync::AsyncCell::shared)
            .value()
            .clone();
        // note that a deadlock might happen without this split between getting
        // the cell and awaiting the value
        let val = cell.get().await;
        Ok(val)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::num::Wrapping;
    use std::sync::Arc;
    use tracing_test::traced_test;

    #[tokio::test]
    #[traced_test]
    async fn test_async_networking() {
        let net = Arc::new(LocalNetworking::default());

        let net1 = Arc::clone(&net);
        let task1 = tokio::spawn(async move {
            let alice = "alice".into();
            let recv = net1
                .receive(&alice, &"rdv".try_into().unwrap(), &123_u128.into())
                .await;
            assert_eq!(recv.unwrap(), Value::Ring64(Wrapping::<u64>(1234)));
        });

        let net2 = Arc::clone(&net);
        let task2 = tokio::spawn(async move {
            let alice = "alice".into();
            let value = Value::Ring64(Wrapping::<u64>(1234));
            net2.send(value, &alice, &"rdv".try_into().unwrap(), &123_u128.into())
                .await
        });

        let _ = tokio::try_join!(task1, task2).unwrap();
    }
}
