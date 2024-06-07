use core::str::FromStr;
use futures::StreamExt;
use tendermint_rpc::{
    client::CompatMode, event::Event, query::Query, Client, Error, Subscription,
    SubscriptionClient, Url, WebSocketClient,
};
use tokio::{task::JoinHandle, time::Duration};
use tracing::{debug, info};

pub struct EventManager {
    url: Url,
    contract_addr: String,
}

impl EventManager {
    pub fn new(url: Url, contract_addr: &str) -> Self {
        EventManager {
            url,
            contract_addr: contract_addr.to_string(),
        }
    }

    pub async fn start(&self, callback: fn(Event) -> Result<(), Error>) -> Result<(), Error> {
        self.websocket_request(self.url.clone(), &self.contract_addr, callback)
            .await
    }

    async fn websocket_request(
        &self,
        url: Url,
        contract_addr: &str,
        callback: fn(Event) -> Result<(), Error>,
    ) -> Result<(), Error> {
        info!("Using WebSocket client to submit request to: {}", url);
        let (client, driver_hdl) = self.start_websocket_client(url).await?;
        let query = Query::from_str(&format!(
            "tm.event='Tx' AND execute._contract_address='{}'",
            contract_addr
        ))
        .unwrap();
        let result = self
            .subscription_client_request(&client, query, None, None, callback)
            .await;
        self.stop_websocket_client(client, driver_hdl).await?;
        result
    }

    async fn subscription_client_request<C>(
        &self,
        client: &C,
        query: Query,
        max_events: Option<u32>,
        max_time: Option<u32>,
        callback: fn(Event) -> Result<(), Error>,
    ) -> Result<(), Error>
    where
        C: SubscriptionClient,
    {
        info!("Creating subscription for query: {}", query);
        let subs = client.subscribe(query).await?;
        match max_time {
            Some(secs) => {
                self.recv_events_with_timeout(subs, max_events, secs, callback)
                    .await
            }
            None => self.recv_events(subs, max_events, callback).await,
        }
    }

    async fn recv_events_with_timeout(
        &self,
        mut subs: Subscription,
        max_events: Option<u32>,
        timeout_secs: u32,
        callback: fn(Event) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let timeout = tokio::time::sleep(Duration::from_secs(timeout_secs as u64));
        let mut event_count = 0u64;
        tokio::pin!(timeout);
        loop {
            tokio::select! {
                result_opt = subs.next() => {
                    let result = match result_opt {
                        Some(r) => r,
                        None => {
                            info!("The server terminated the subscription");
                            return Ok(());
                        }
                    };
                    let event = result?;
                    callback(event)?;
                    event_count += 1;
                    if let Some(me) = max_events {
                        if event_count >= (me as u64) {
                            info!("Reached maximum number of events: {}", me);
                            return Ok(());
                        }
                    }
                }
                _ = &mut timeout => {
                    info!("Reached event receive timeout of {} seconds", timeout_secs);
                    return Ok(())
                }
            }
        }
    }

    async fn recv_events(
        &self,
        mut subs: Subscription,
        max_events: Option<u32>,
        callback: fn(Event) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let mut event_count = 0u64;
        while let Some(result) = subs.next().await {
            let event = result?;
            callback(event)?;
            event_count += 1;
            if let Some(me) = max_events {
                if event_count >= (me as u64) {
                    info!("Reached maximum number of events: {}", me);
                    return Ok(());
                }
            }
        }
        info!("The server terminated the subscription");
        Ok(())
    }

    async fn start_websocket_client(
        &self,
        url: Url,
    ) -> Result<(WebSocketClient, JoinHandle<Result<(), Error>>), Error> {
        let (client, driver) = WebSocketClient::new(url.clone()).await?;
        let driver_hdl = tokio::spawn(async move { driver.run().await });
        let status = client.status().await?;
        let compat_mode = CompatMode::from_version(status.node_info.version)?;
        if compat_mode == CompatMode::latest() {
            debug!("Using compatibility mode {}", compat_mode);
            Ok((client, driver_hdl))
        } else {
            debug!("Reconnecting with compatibility mode {}", compat_mode);
            self.stop_websocket_client(client, driver_hdl).await?;
            let (client, driver) = WebSocketClient::builder(url.try_into()?)
                .compat_mode(compat_mode)
                .build()
                .await?;
            let driver_hdl = tokio::spawn(async move { driver.run().await });
            Ok((client, driver_hdl))
        }
    }

    async fn stop_websocket_client(
        &self,
        client: WebSocketClient,
        driver_hdl: JoinHandle<Result<(), Error>>,
    ) -> Result<(), Error> {
        client.close()?;
        driver_hdl.await.map_err(Error::join)?
    }
}
