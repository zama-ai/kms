use super::*;
use std::sync::Arc;

/// A simple implementation of asynchronous networking for local execution.
///
/// This implementation is intended for local development/testing purposes
/// only. It simply stores all values in a hashmap without any actual networking.
pub struct LocalNetworking {
    store: Arc<async_cell::sync::AsyncCell<Value>>,
    session_id: SessionId,
}

#[async_trait]
impl Networking for LocalNetworking {
    async fn send(&self, val: &Value, _receiver: &Identity) -> anyhow::Result<()> {
        tracing::debug!("Async sending; sid:{}", self.session_id);
        let cell = self.store.clone();
        cell.set(val.clone());
        Ok(())
    }

    async fn receive(&self, _sender: &Identity) -> anyhow::Result<Value> {
        tracing::debug!("Async receiving; sid:{}", self.session_id);
        let cell = self.store.clone();
        let val = cell.get().await;
        Ok(val)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::num::Wrapping;
    use tracing_test::traced_test;

    #[tokio::test]
    #[traced_test]
    async fn test_async_networking() {
        use std::sync::Arc;

        let net = Arc::new(LocalNetworking {
            session_id: 123_u128.into(),
            store: Default::default(),
        });

        let net1 = Arc::clone(&net);
        let task1 = tokio::spawn(async move {
            let alice = Identity(0_u64);
            let recv = net1.receive(&alice).await;
            assert_eq!(recv.unwrap(), Value::Ring64(Wrapping::<u64>(1234)));
        });

        let net2 = Arc::clone(&net);
        let task2 = tokio::spawn(async move {
            let bob = Identity(1_u64);
            let value = Value::Ring64(Wrapping::<u64>(1234));
            net2.send(&value, &bob).await
        });

        let _ = tokio::try_join!(task1, task2).unwrap();
    }
}
