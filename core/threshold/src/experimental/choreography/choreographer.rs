use crate::choreography::grpc::gen::{
    DecryptionRequest, KeygenRequest, PubkeyRequest, RetrieveResultsRequest,
};
use crate::execution::constants::INPUT_PARTY_ID;
use crate::execution::runtime::party::Role;
use crate::experimental::bgv::basics::PublicBgvKeySet;
use crate::experimental::choreography::grpc::ComputationOutputs;
use crate::{
    choreography::choreographer::ChoreoRuntime,
    execution::runtime::session::DecryptionMode,
    experimental::{
        algebra::{levels::LevelEll, ntt::N65536},
        bgv::basics::BGVCiphertext,
    },
    session_id::SessionId,
};
use std::collections::HashMap;
use std::time::Duration;
use tokio::task::JoinSet;

#[derive(Debug)]
pub struct GrpcOutputs {
    pub outputs: HashMap<String, Vec<u32>>,
    pub elapsed_times: Option<HashMap<Role, Vec<Duration>>>,
}

impl ChoreoRuntime {
    pub async fn local_bgv_keygen(
        &self,
        threshold: u32,
    ) -> Result<PublicBgvKeySet, Box<dyn std::error::Error>> {
        let epoch_id = bincode::serialize(&SessionId(0))?;
        tracing::debug!("role assignemnts: {:?}", self.role_assignments);
        let role_assignment = bincode::serialize(&self.role_assignments)?;
        let params = bincode::serialize(&None::<u8>)?;

        for channel in self.channels.values() {
            let mut client = self.new_client(channel.clone());
            let request = KeygenRequest {
                epoch_id: epoch_id.clone(),
                role_assignment: role_assignment.clone(),
                threshold,
                params: params.clone(),
            };
            tracing::debug!("launching BGV keygen to {:?}", channel);
            let _ = client.keygen(request).await?;
        }
        for (role, channel) in self.channels.iter() {
            if role.one_based() == INPUT_PARTY_ID {
                let mut client = self.new_client(channel.clone());
                let request = PubkeyRequest { epoch_id };
                tracing::debug!("launching pubkey request");
                let response = client.retrieve_pubkey(request).await?;
                let pk = bincode::deserialize::<PublicBgvKeySet>(&response.get_ref().pubkey)?;
                return Ok(pk);
            }
        }

        Err("No Public Key generated!".into())
    }

    pub async fn experimental_threshold_decrypt(
        &self,
        mode: &DecryptionMode,
        threshold: u32,
        ct: &BGVCiphertext<LevelEll, N65536>,
    ) -> anyhow::Result<SessionId> {
        let mode_s = bincode::serialize(mode)?;
        let role_assignment = bincode::serialize(&self.role_assignments)?;
        let ciphertext = bincode::serialize(ct)?;
        self.spawn_bgv_threshold_decrypt(&mode_s, &role_assignment, threshold, &ciphertext)
            .await?;
        SessionId::from_bgv_ct(ct)
    }

    async fn spawn_bgv_threshold_decrypt(
        &self,
        mode: &[u8],
        role_assignment: &[u8],
        threshold: u32,
        ciphertext: &[u8],
    ) -> anyhow::Result<()> {
        let mut join_set = JoinSet::new();
        self.channels.values().for_each(|channel| {
            let mut client = self.new_client(channel.clone());

            let request = DecryptionRequest {
                mode: mode.to_vec(),
                role_assignment: role_assignment.to_vec(),
                threshold,
                ciphertext: ciphertext.to_vec(),
            };

            tracing::debug!("launching the decryption with proto to {:?}", channel);
            join_set.spawn(async move { client.threshold_decrypt(request).await });
        });
        while let Some(response) = join_set.join_next().await {
            response??;
        }
        Ok(())
    }

    pub async fn experimental_retrieve_results(
        &self,
        session_id: &SessionId,
        session_range: u32,
    ) -> Result<GrpcOutputs, Box<dyn std::error::Error>> {
        let session_id = bincode::serialize(&session_id)?;

        let mut combined_outputs = HashMap::new();
        let mut combined_stats = HashMap::new();

        for (role, channel) in self.channels.iter() {
            tracing::info!("Init retrieving results from {:?}", role);
            let mut client = self.new_client(channel.clone());

            let request = RetrieveResultsRequest {
                session_id: session_id.clone(),
                session_range,
            };
            let resp = client.retrieve_results(request).await?;

            let computation_output =
                bincode::deserialize::<ComputationOutputs>(&resp.get_ref().values)?;
            // only party 1 reconstructs at them moment, so ignore other outputs (they would override party 1 outputs)
            if role.one_based() == INPUT_PARTY_ID {
                combined_outputs.extend(computation_output.outputs);
            }

            if let Some(time) = computation_output.elapsed_time {
                combined_stats
                    .entry(*role)
                    .or_insert_with(Vec::new)
                    .push(time);
            }
            tracing::info!("Retrieved results from {:?}", role);
        }

        if combined_stats.is_empty() {
            Ok(GrpcOutputs {
                outputs: combined_outputs,
                elapsed_times: None,
            })
        } else {
            Ok(GrpcOutputs {
                outputs: combined_outputs,
                elapsed_times: Some(combined_stats),
            })
        }
    }
}
