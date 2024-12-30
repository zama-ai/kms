use crate::config::ConnectorConfig;

/// Connector trait that listen to blockchain events.
#[async_trait::async_trait]
pub trait Connector {
    async fn listen_for_events(self, catch_up_num_blocks: Option<usize>) -> anyhow::Result<()>;
}

pub mod gateway_connector;
pub mod kms_core_connector;

pub async fn listen(
    config: ConnectorConfig,
    catch_up_num_blocks: Option<usize>,
) -> anyhow::Result<()> {
    kms_core_connector::KmsCoreConnector::new_with_config(config)
        .await?
        .listen_for_events(catch_up_num_blocks)
        .await
}
