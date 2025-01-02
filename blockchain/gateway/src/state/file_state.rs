use std::{
    collections::{hash_map::Entry, HashMap},
    fs::{File, OpenOptions},
    io::Read,
    os::unix::fs::FileExt,
    sync::Arc,
};

use anyhow::anyhow;
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, RwLock, RwLockWriteGuard};

use crate::state::GatewayEventState;

use super::GatewayInnerEvent;

type MapState = HashMap<GatewayInnerEvent, GatewayEventState>;
#[derive(Default, Serialize, Deserialize)]
pub struct InnerState {
    kms_chain_height: Option<u64>,
    main_chain_height: Option<u64>,
    // This is the state that gets updated by the current queries
    state: MapState,
}
// TODO: May want to generalize to
// something else than file sometime

/// The state is made of Arcs
/// and can be cloned around
#[derive(Clone)]
pub struct GatewayState {
    file: Arc<Mutex<File>>,
    inner_state: Arc<RwLock<InnerState>>,
}

impl GatewayState {
    fn new_state(path: &str) -> anyhow::Result<Self> {
        let file = File::create(path)?;
        Ok(Self {
            file: Arc::new(Mutex::new(file)),
            inner_state: Arc::new(RwLock::new(InnerState::default())),
        })
    }

    // Returns the state, the inner state that was saved and that is used for catchup
    // as well as from which block do we need to catchup on the KMS BC
    pub fn restore_state(path: &str) -> anyhow::Result<(Self, Option<MapState>, Option<usize>)> {
        match OpenOptions::new().read(true).write(true).open(path) {
            Ok(mut file) => {
                let mut content = vec![];
                file.read_to_end(&mut content)?;

                let inner_state: InnerState = bincode::deserialize(&content)?;
                let state = inner_state.state.clone();
                let kms_bc_starting_block = inner_state.kms_chain_height.map(|x| x as usize);

                Ok((
                    Self {
                        file: Arc::new(Mutex::new(file)),
                        inner_state: Arc::new(RwLock::new(inner_state)),
                    },
                    Some(state),
                    // Retry the last block seen just to be sure
                    kms_bc_starting_block,
                ))
            }
            Err(_) => Ok((Self::new_state(path)?, None, None)),
        }
    }

    // Accepts a lock on the state to make this "atomic"
    // if called from a function that holds a lock already
    async fn save_state(
        &self,
        inner_lock: Option<RwLockWriteGuard<'_, InnerState>>,
    ) -> anyhow::Result<()> {
        let content = if let Some(inner_lock) = inner_lock {
            bincode::serialize(&(*inner_lock))?
        } else {
            bincode::serialize(&(*self.inner_state.read().await))?
        };
        let file = self.file.lock().await;
        (*file).write_all_at(&content, 0)?;
        tracing::info!("State has been saved !");
        Ok(())
    }

    // Returns true if the event was added, false if the entry already existed
    pub async fn add_event(&self, gateway_event: GatewayInnerEvent) -> bool {
        tracing::info!("Added event {:?} to state ", gateway_event);
        let mut inner_state = self.inner_state.write().await;
        let entry = (inner_state.state).entry(gateway_event);
        match entry {
            Entry::Occupied(_occupied_entry) => false,
            Entry::Vacant(vacant_entry) => {
                vacant_entry.insert(GatewayEventState::Received);
                true
            }
        }
    }

    pub async fn update_event(
        &self,
        gateway_event: &GatewayInnerEvent,
        kms_event: GatewayEventState,
    ) -> anyhow::Result<()> {
        let kms_chain_height_update = match &kms_event {
            GatewayEventState::Received => None,
            GatewayEventState::SentToKmsBc(kms_event_state) => {
                Some(kms_event_state.get_kms_height())
            }
            GatewayEventState::ResultFromKmsBc(kms_event_state) => {
                Some(kms_event_state.get_kms_height())
            }
        };
        let mut inner_state = self.inner_state.write().await;
        let entry = inner_state.state.get_mut(gateway_event);
        let entry = entry.ok_or_else(|| anyhow!("Trying to update an empty entry"))?;
        tracing::info!("Updated event {:?} to {:?} ", gateway_event, kms_event);
        (*entry) = kms_event;
        if let Some(kms_height_update) = kms_chain_height_update {
            inner_state.kms_chain_height = Some(kms_height_update);
        }
        self.save_state(Some(inner_state)).await
    }

    pub async fn remove_event(
        &self,
        gateway_event: &GatewayInnerEvent,
    ) -> anyhow::Result<GatewayEventState> {
        let mut inner_state = self.inner_state.write().await;
        let entry = inner_state
            .state
            .remove(gateway_event)
            .ok_or_else(|| anyhow!("Trying to remove an entry that does not exist"))?;

        tracing::info!("Removed event {:?} from state", gateway_event);
        self.save_state(Some(inner_state)).await?;
        Ok(entry)
    }

    pub async fn get_main_chain_height(&self) -> Option<u64> {
        self.inner_state.read().await.main_chain_height
    }

    pub async fn update_main_chain_height(&self, new_value: u64) -> anyhow::Result<()> {
        let mut inner_state = self.inner_state.write().await;
        inner_state.main_chain_height = Some(new_value);
        self.save_state(Some(inner_state)).await
    }
}

#[cfg(test)]
mod tests {
    use events::HexVector;

    use crate::state::{
        file_state::GatewayState, ApiReencryptValues, GatewayEventState, GatewayInnerEvent,
    };

    #[tokio::test]
    async fn test_state() {
        let state = GatewayState::new_state("test.state").unwrap();

        let values = ApiReencryptValues {
            signature: HexVector::from(vec![1, 2, 3]),
            client_address: "0x1234567890abcdef".to_string(),
            enc_key: HexVector::from(vec![7, 8, 9]),
            ciphertext_handle: HexVector::from(vec![10, 11, 12]),
            eip712_verifying_contract: "0x1234567890abcdef".to_string(),
        };

        let event = GatewayInnerEvent::Reencryption(values);
        let status = state.add_event(event.clone()).await;
        assert!(status);

        let status_bis = state.add_event(event.clone()).await;
        assert!(!status_bis);

        state.save_state(None).await.unwrap();
        drop(state);

        let (new_state, _old_state, _kms_blockchain_height) =
            GatewayState::restore_state("test.state").unwrap();
        {
            let inner_state = new_state.inner_state.read().await;

            let value = inner_state.state.get(&event).unwrap();
            assert_eq!(value, &GatewayEventState::Received);
        }
        drop(new_state);

        std::fs::remove_file("test.state").unwrap();
    }
}
