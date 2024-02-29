use super::grpc::gen::CrsRequest;
use crate::{
    algebra::base_ring::Z64,
    choreography::grpc::gen::{
        choreography_client::ChoreographyClient, CrsCeremonyRequest, DecryptionRequest,
        KeygenRequest, PubkeyRequest, RetrieveResultsRequest,
    },
    computation::SessionId,
    execution::{
        constants::INPUT_PARTY_ID,
        runtime::party::{Identity, Role},
        zk::ceremony::PublicParameter,
    },
    lwe::Ciphertext64,
    networking::constants::{MAX_EN_DECODE_MESSAGE_SIZE, NETWORK_TIMEOUT_LONG},
};
use crate::{choreography::grpc::ComputationOutputs, execution::runtime::session::DecryptionMode};
use crate::{execution::runtime::session::SetupMode, lwe::ThresholdLWEParameters};
use std::{collections::HashMap, time::Duration};
use tokio::task::JoinSet;
use tonic::transport::{Channel, ClientTlsConfig, Uri};

pub struct ChoreoRuntime {
    role_assignments: HashMap<Role, Identity>,
    channels: HashMap<Role, Channel>,
}

#[derive(Debug)]
pub struct GrpcOutputs {
    pub outputs: HashMap<String, Z64>,
    pub elapsed_times: Option<HashMap<Role, Vec<Duration>>>,
}

pub type NetworkTopology = HashMap<Role, Uri>;

impl ChoreoRuntime {
    pub fn new(
        role_assignments: HashMap<Role, Identity>,
        tls_config: Option<ClientTlsConfig>,
    ) -> Result<ChoreoRuntime, Box<dyn std::error::Error>> {
        let network_topology: NetworkTopology = role_assignments
            .iter()
            .map(|(role, id)| {
                let uri: Uri = id.to_string().parse()?;
                Ok((*role, uri))
            })
            .collect::<Result<NetworkTopology, Box<dyn std::error::Error>>>()?;
        Self::new_with_net_topology(role_assignments.clone(), tls_config, network_topology)
    }

    pub fn new_with_net_topology(
        role_assignments: HashMap<Role, Identity>,
        tls_config: Option<ClientTlsConfig>,
        network_topology: NetworkTopology,
    ) -> Result<ChoreoRuntime, Box<dyn std::error::Error>> {
        let channels = network_topology
            .iter()
            .map(|(role, host)| {
                let endpoint: &Uri = host;
                tracing::debug!("connecting to endpoint: {:?}", endpoint);
                let mut channel = Channel::builder(endpoint.clone());
                if let Some(ref tls_config) = tls_config {
                    channel = channel.tls_config(tls_config.clone())?;
                };
                let channel = channel.timeout(*NETWORK_TIMEOUT_LONG).connect_lazy();
                Ok((*role, channel))
            })
            .collect::<Result<_, Box<dyn std::error::Error>>>()?;

        Ok(ChoreoRuntime {
            role_assignments,
            channels,
        })
    }

    fn new_client(&self, channel: Channel) -> ChoreographyClient<Channel> {
        ChoreographyClient::new(channel)
            .max_decoding_message_size(*MAX_EN_DECODE_MESSAGE_SIZE)
            .max_encoding_message_size(*MAX_EN_DECODE_MESSAGE_SIZE)
    }

    pub async fn initiate_threshold_decryption(
        &self,
        mode: &DecryptionMode,
        threshold: u32,
        ct: &Ciphertext64,
    ) -> anyhow::Result<SessionId> {
        let mode_s = bincode::serialize(mode)?;
        let role_assignment = bincode::serialize(&self.role_assignments)?;
        let ciphertext = bincode::serialize(ct)?;
        self.spawn_threshold_decrypt(&mode_s, &role_assignment, threshold, &ciphertext)
            .await?;
        SessionId::new(ct)
    }

    async fn spawn_threshold_decrypt(
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

    pub async fn initiate_retrieve_results(
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

            for co in bincode::deserialize::<Vec<ComputationOutputs>>(&resp.get_ref().values)? {
                // only party 1 reconstructs at them moment, so ignore other outputs (they would override party 1 outputs)
                if role.one_based() == INPUT_PARTY_ID {
                    combined_outputs.extend(co.outputs);
                }

                if let Some(time) = co.elapsed_time {
                    combined_stats
                        .entry(*role)
                        .or_insert_with(Vec::new)
                        .push(time);
                }
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

    pub async fn initiate_keygen(
        &self,
        epoch_id: &SessionId,
        threshold: u32,
        params: ThresholdLWEParameters,
        setup_mode: SetupMode,
    ) -> Result<tfhe::CompactPublicKey, Box<dyn std::error::Error>> {
        let epoch_id = bincode::serialize(epoch_id)?;
        let role_assignment = bincode::serialize(&self.role_assignments)?;
        let params = bincode::serialize(&params)?;
        let setup_mode = bincode::serialize(&setup_mode)?;

        for channel in self.channels.values() {
            let mut client = self.new_client(channel.clone());

            let request = KeygenRequest {
                epoch_id: epoch_id.clone(),
                role_assignment: role_assignment.clone(),
                threshold,
                params: params.clone(),
                setup_mode: setup_mode.clone(),
            };

            tracing::debug!("launching keygen to {:?}", channel);
            let _ = client.keygen(request).await?;
        }

        for (role, channel) in self.channels.iter() {
            if role.one_based() == INPUT_PARTY_ID {
                let mut client = self.new_client(channel.clone());
                let request = PubkeyRequest { epoch_id };
                let response = client.retrieve_pubkey(request).await?;
                let pk =
                    bincode::deserialize::<tfhe::CompactPublicKey>(&response.get_ref().pubkey)?;
                return Ok(pk);
            }
        }

        Err("No Public Key generated!".into())
    }

    pub async fn initiate_retrieve_pubkey(
        &self,
        epoch_id: &SessionId,
    ) -> Result<tfhe::CompactPublicKey, Box<dyn std::error::Error>> {
        let epoch_id = bincode::serialize(epoch_id)?;

        for (role, channel) in self.channels.iter() {
            if role.one_based() == INPUT_PARTY_ID {
                let mut client = self.new_client(channel.clone());
                let request = PubkeyRequest { epoch_id };
                let response = client.retrieve_pubkey(request).await?;
                let pk =
                    bincode::deserialize::<tfhe::CompactPublicKey>(&response.get_ref().pubkey)?;
                return Ok(pk);
            }
        }

        Err("No Public Key received!".into())
    }

    pub async fn initiate_crs_ceremony(
        &self,
        epoch_id: &SessionId,
        threshold: u32,
        witness_dim: u32,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let epoch_id = bincode::serialize(epoch_id)?;
        let role_assignment = bincode::serialize(&self.role_assignments)?;

        for channel in self.channels.values() {
            let mut client = self.new_client(channel.clone());

            let request = CrsCeremonyRequest {
                epoch_id: epoch_id.clone(),
                role_assignment: role_assignment.clone(),
                threshold,
                witness_dim,
            };

            tracing::debug!("Launching CRS ceremony to {:?}", channel);
            let _ = client.crs_ceremony(request).await?;
        }
        Ok(())
    }

    pub async fn initiate_retrieve_crs(
        &self,
        epoch_id: &SessionId,
    ) -> Result<(PublicParameter, f32), Box<dyn std::error::Error>> {
        let epoch_id = bincode::serialize(epoch_id)?;

        for (role, channel) in self.channels.iter() {
            if role.one_based() == INPUT_PARTY_ID {
                let mut client = self.new_client(channel.clone());
                let request = CrsRequest { epoch_id };
                let response = client.retrieve_crs(request).await?;
                let crs = bincode::deserialize::<PublicParameter>(&response.get_ref().crs)?;
                let dur = response.get_ref().duration_secs;
                return Ok((crs, dur));
            }
        }

        Err("No CRS received!".into())
    }
}
