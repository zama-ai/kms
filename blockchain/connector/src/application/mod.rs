use clap::Subcommand;

use crate::conf::ConnectorConfig;

#[derive(Debug, Clone, Subcommand)]
pub enum Mode {
    KmsCore,
    Oracle,
}

//TODO(#1694): RENAME THIS CONNECTOR
#[async_trait::async_trait]
pub trait SyncHandler {
    async fn listen_for_events(self, catch_up_num_blocks: Option<usize>) -> anyhow::Result<()>;
}

pub mod kms_core_sync;
pub mod oracle_sync;

pub async fn listen(
    config: ConnectorConfig,
    mode: Mode,
    catch_up_num_blocks: Option<usize>,
) -> anyhow::Result<()> {
    match mode {
        Mode::KmsCore => {
            kms_core_sync::KmsCoreSyncHandler::new_with_config(config)
                .await?
                .listen_for_events(catch_up_num_blocks)
                .await?
        }
        Mode::Oracle => {
            oracle_sync::OracleSyncHandler::new_with_config(config)
                .await?
                .listen_for_events(catch_up_num_blocks)
                .await?
        }
    }
    Ok(())
}
