use super::*;
use anyhow::anyhow;
use dashmap::mapref::one::RefMut;
use dashmap::DashMap;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::sync::mpsc::*;

/// A simple implementation of asynchronous networking for local execution.
///
/// This implementation is intended for local development/testing purposes
/// only. It simply stores all values in a hashmap without any actual networking.
pub struct LocalNetworking {
    pub session_id: SessionId,
    pub send_channels: DashMap<Identity, Arc<UnboundedSender<Value>>>,
    pub recv_channels: DashMap<Identity, UnboundedReceiver<Value>>,
}

fn cell_send(
    receiver: &Identity,
    send_channels: &DashMap<Identity, Arc<UnboundedSender<Value>>>,
    recv_channels: &DashMap<Identity, UnboundedReceiver<Value>>,
) -> Arc<UnboundedSender<Value>> {
    let cell = send_channels
        .entry(receiver.clone())
        .or_insert_with(|| {
            let (tx, rx) = mpsc::unbounded_channel::<Value>();
            recv_channels.insert(receiver.clone(), rx);
            Arc::new(tx)
        })
        .clone();
    cell
}

fn cell_receive<'a>(
    sender: &'a Identity,
    send_channels: &'a DashMap<Identity, Arc<UnboundedSender<Value>>>,
    recv_channels: &'a DashMap<Identity, UnboundedReceiver<Value>>,
) -> RefMut<'a, Identity, UnboundedReceiver<Value>> {
    let cell = recv_channels.entry(sender.clone()).or_insert_with(|| {
        let (tx, rx) = mpsc::unbounded_channel::<Value>();
        send_channels.insert(sender.clone(), Arc::new(tx));
        rx
    });
    cell
}

#[async_trait]
impl Networking for LocalNetworking {
    async fn send(
        &self,
        val: &Value,
        receiver: &Identity,
        _session_id: &SessionId,
    ) -> anyhow::Result<()> {
        tracing::debug!("Async sending; sid:{}", self.session_id);
        let cell = cell_send(receiver, &self.send_channels, &self.recv_channels);
        let _ = cell.send(val.clone());
        Ok(())
    }

    async fn receive(&self, sender: &Identity, _session_id: &SessionId) -> anyhow::Result<Value> {
        tracing::debug!("Async receiving; sid:{}", self.session_id);
        let mut cell = cell_receive(sender, &self.send_channels, &self.recv_channels);
        let value = cell
            .value_mut()
            .recv()
            .await
            .ok_or(anyhow!("Couldn't receive data from channel"))?;
        Ok(value)
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
            recv_channels: Default::default(),
            send_channels: Default::default(),
        });

        let net1 = Arc::clone(&net);
        let task1 = tokio::spawn(async move {
            let alice = "alice".into();
            let recv = net1.receive(&alice, &123_u128.into()).await;
            assert_eq!(recv.unwrap(), Value::Ring64(Wrapping::<u64>(1234)));
        });

        let net2 = Arc::clone(&net);
        let task2 = tokio::spawn(async move {
            let alice = "alice".into();
            let value = Value::Ring64(Wrapping::<u64>(1234));
            net2.send(&value, &alice, &123_u128.into()).await
        });

        let _ = tokio::try_join!(task1, task2).unwrap();
    }
}
