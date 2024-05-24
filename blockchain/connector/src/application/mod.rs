use clap::Subcommand;

use crate::conf::ConnectorConfig;

#[derive(Debug, Clone, Subcommand)]
pub enum Mode {
    KmsCore,
    Oracle,
}

#[async_trait::async_trait]
pub trait SyncHandler {
    async fn listen_for_events(self) -> anyhow::Result<()>;
}

pub mod kms_core_sync;
pub mod oracle_sync;

pub async fn listen(config: ConnectorConfig, mode: Mode) -> anyhow::Result<()> {
    match mode {
        Mode::KmsCore => {
            kms_core_sync::KmsCoreSyncHandler::new_with_config(config)
                .await?
                .listen_for_events()
                .await?
        }
        Mode::Oracle => {
            oracle_sync::OracleSyncHandler::new_with_config(config)
                .await?
                .listen_for_events()
                .await?
        }
    }
    Ok(())
}
