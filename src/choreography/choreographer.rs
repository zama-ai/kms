use crate::choreography::grpc::ComputationOutputs;
use crate::lwe::ThresholdLWEParameters;
use crate::{
    choreography::grpc::gen::{
        choreography_client::ChoreographyClient, DecryptionRequest, KeygenRequest,
        LaunchComputationRequest, PubkeyRequest, RetrieveResultsRequest,
    },
    circuit::Circuit,
    computation::SessionId,
    execution::{
        constants::INPUT_PARTY_ID,
        distributed::{DecryptionMode, SetupMode},
        party::{Identity, Role},
    },
    lwe::{Ciphertext64, PublicKey},
    value::Value,
};
use std::{collections::HashMap, time::Duration};
use tonic::transport::{Channel, ClientTlsConfig, Uri};

pub struct ChoreoRuntime {
    role_assignments: HashMap<Role, Identity>,
    channels: HashMap<Role, Channel>,
}

#[derive(Debug)]
pub struct GrpcOutputs {
    pub outputs: HashMap<String, Vec<Value>>,
    pub elapsed_times: Option<HashMap<Role, Vec<Duration>>>,
}

impl ChoreoRuntime {
    pub fn new(
        role_assignments: HashMap<Role, Identity>,
        tls_config: Option<ClientTlsConfig>,
    ) -> Result<ChoreoRuntime, Box<dyn std::error::Error>> {
        let channels = role_assignments
            .iter()
            .map(|(role, identity)| {
                let endpoint: Uri = format!("http://{}", identity).parse()?;
                tracing::debug!("connecting to endpoint: {:?}", endpoint);
                let mut channel = Channel::builder(endpoint);
                if let Some(ref tls_config) = tls_config {
                    channel = channel.tls_config(tls_config.clone())?;
                };
                let channel = channel.connect_lazy();
                Ok((role.clone(), channel))
            })
            .collect::<Result<_, Box<dyn std::error::Error>>>()?;

        Ok(ChoreoRuntime {
            role_assignments,
            channels,
        })
    }

    pub async fn initiate_launch_computation_debug(
        &self,
        computation: &Circuit,
        threshold: u8,
        ct: &Ciphertext64,
    ) -> anyhow::Result<SessionId> {
        let computation = bincode::serialize(computation)?;
        let role_assignment = bincode::serialize(&self.role_assignments)?;
        let threshold = bincode::serialize(&threshold)?;
        let ciphertext = bincode::serialize(ct)?;

        for channel in self.channels.values() {
            let mut client = ChoreographyClient::new(channel.clone());

            let request = LaunchComputationRequest {
                computation: computation.clone(),
                role_assignment: role_assignment.clone(),
                threshold: threshold.clone(),
                ciphertext: ciphertext.clone(),
            };

            tracing::debug!("launching the computation to {:?}", channel);
            let _response = client.launch_computation_debug(request).await?;
        }

        SessionId::new(ct)
    }

    pub async fn initiate_threshold_decryption(
        &self,
        mode: &DecryptionMode,
        threshold: u8,
        ct: &Ciphertext64,
    ) -> anyhow::Result<SessionId> {
        let mode_s = bincode::serialize(mode)?;
        let role_assignment = bincode::serialize(&self.role_assignments)?;
        let threshold = bincode::serialize(&threshold)?;
        let ciphertext = bincode::serialize(ct)?;

        for channel in self.channels.values() {
            let mut client = ChoreographyClient::new(channel.clone());

            let request = DecryptionRequest {
                mode: mode_s.clone(),
                role_assignment: role_assignment.clone(),
                threshold: threshold.clone(),
                ciphertext: ciphertext.clone(),
            };

            tracing::debug!(
                "launching the decryption with proto {} to {:?}",
                mode,
                channel
            );
            let _response = client.threshold_decrypt(request).await?;
        }

        SessionId::new(ct)
    }

    pub async fn initiate_retrieve_results(
        &self,
        session_id: &SessionId,
        session_range: u32,
    ) -> Result<GrpcOutputs, Box<dyn std::error::Error>> {
        let session_id = bincode::serialize(&session_id)?;

        let mut combined_outputs = HashMap::new();
        let mut combined_stats = HashMap::new();

        for (role, channel) in self.channels.iter() {
            let mut client = ChoreographyClient::new(channel.clone());

            let request = RetrieveResultsRequest {
                session_id: session_id.clone(),
                session_range,
            };

            let response = client.retrieve_results(request).await?;

            for co in bincode::deserialize::<Vec<ComputationOutputs>>(&response.get_ref().values)? {
                // only party 1 reconstructs at them moment, so ignore other outputs (they would override party 1 outputs)
                if role.party_id() == INPUT_PARTY_ID {
                    combined_outputs.extend(co.outputs);
                }

                if let Some(time) = co.elapsed_time {
                    combined_stats
                        .entry(role.clone())
                        .or_insert_with(Vec::new)
                        .push(time);
                }
            }
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

    pub async fn initiate_keygen(
        &self,
        epoch_id: &SessionId,
        threshold: u8,
        params: ThresholdLWEParameters,
        seed: u64,
        setup_mode: SetupMode,
    ) -> Result<PublicKey, Box<dyn std::error::Error>> {
        let epoch_id = bincode::serialize(epoch_id)?;
        let role_assignment = bincode::serialize(&self.role_assignments)?;
        let threshold = bincode::serialize(&threshold)?;
        let params = bincode::serialize(&params)?;
        let setup_mode = bincode::serialize(&setup_mode)?;

        for channel in self.channels.values() {
            let mut client = ChoreographyClient::new(channel.clone());

            let request = KeygenRequest {
                epoch_id: epoch_id.clone(),
                role_assignment: role_assignment.clone(),
                threshold: threshold.clone(),
                params: params.clone(),
                seed, // use an externally supplied seed until we have implemented, e.g. AgreeRandom
                setup_mode: setup_mode.clone(),
            };

            tracing::debug!("launching keygen to {:?}", channel);
            let _ = client.keygen(request).await?;
        }

        for (role, channel) in self.channels.iter() {
            if role.party_id() == INPUT_PARTY_ID {
                let mut client = ChoreographyClient::new(channel.clone());
                let request = PubkeyRequest { epoch_id };
                let response = client.retrieve_pubkey(request).await?;
                let pk = bincode::deserialize::<PublicKey>(&response.get_ref().pubkey)?;
                return Ok(pk);
            }
        }

        Err("No Public Key generated!".into())
    }

    pub async fn initiate_retrieve_pubkey(
        &self,
        epoch_id: &SessionId,
    ) -> Result<PublicKey, Box<dyn std::error::Error>> {
        let epoch_id = bincode::serialize(epoch_id)?;

        for (role, channel) in self.channels.iter() {
            if role.party_id() == INPUT_PARTY_ID {
                let mut client = ChoreographyClient::new(channel.clone());
                let request = PubkeyRequest { epoch_id };
                let response = client.retrieve_pubkey(request).await?;
                let pk = bincode::deserialize::<PublicKey>(&response.get_ref().pubkey)?;
                return Ok(pk);
            }
        }

        Err("No Public Key received!".into())
    }
}
