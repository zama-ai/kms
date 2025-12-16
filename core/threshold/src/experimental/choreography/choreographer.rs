//! Choreographer is the client of the grpc choreography service.
//! It is not really an issue to have "unsafe" code here (e.g. unsafe deserialization)
//! as this is meant for testing and benchmarking, and definitely not for production use.
use crate::choreography::grpc::gen::{
    PreprocKeyGenRequest, PrssInitRequest, ThresholdDecryptRequest, ThresholdDecryptResultRequest,
    ThresholdKeyGenRequest, ThresholdKeyGenResultRequest,
};
use crate::execution::runtime::party::Role;
use crate::experimental::algebra::levels::{LevelEll, LevelKsw};
use crate::experimental::algebra::ntt::N65536;
use crate::experimental::bgv::basics::{LevelEllCiphertext, PublicKey};
use crate::{choreography::choreographer::ChoreoRuntime, session_id::SessionId};
use std::collections::HashMap;
use tokio::task::JoinSet;
use tokio::time::Duration;
use tracing::{instrument, Instrument};

use super::requests::{
    PreprocKeyGenParams, PrssInitParams, SupportedRing, ThresholdDecryptParams,
    ThresholdKeyGenParams, ThresholdKeyGenResultParams,
};

#[derive(Debug)]
pub struct GrpcOutputs {
    pub outputs: HashMap<String, Vec<u32>>,
    pub elapsed_times: Option<HashMap<Role, Vec<Duration>>>,
}

impl ChoreoRuntime {
    #[instrument(name = "PRSS-INIT Request (BGV)", skip(self, session_id), fields(sid = ?session_id))]
    pub async fn bgv_inititate_prss_init(
        &self,
        session_id: SessionId,
        ring: SupportedRing,
        threshold: u32,
        seed: Option<u64>,
    ) -> anyhow::Result<()> {
        let role_assignment = bc2wrap::serialize(&self.role_assignments)?;

        let prss_params = bc2wrap::serialize(&PrssInitParams { session_id, ring })?;

        let mut join_set = JoinSet::new();
        self.channels.values().for_each(|channel| {
            let mut client = self.new_client(channel.clone());

            let request = PrssInitRequest {
                role_assignment: role_assignment.to_vec(),
                threshold,
                params: prss_params.to_vec(),
                seed,
            };

            join_set.spawn(
                async move { client.prss_init(request).await }.instrument(tracing::Span::current()),
            );
        });
        while let Some(response) = join_set.join_next().await {
            response??;
        }

        Ok(())
    }

    #[instrument(name = "DKG-Preproc Request (BGV)", skip(self, session_id), fields(sid = ?session_id))]
    pub async fn bgv_initiate_preproc_keygen(
        &self,
        session_id: SessionId,
        num_sessions: u32,
        threshold: u32,
        seed: Option<u64>,
    ) -> anyhow::Result<SessionId> {
        let role_assignment = bc2wrap::serialize(&self.role_assignments)?;
        let preproc_kg_params = bc2wrap::serialize(&PreprocKeyGenParams {
            session_id,
            num_sessions,
        })?;

        let mut join_set = JoinSet::new();
        self.channels.values().for_each(|channel| {
            let mut client = self.new_client(channel.clone());
            let request = PreprocKeyGenRequest {
                role_assignment: role_assignment.to_vec(),
                threshold,
                params: preproc_kg_params.to_vec(),
                seed,
            };

            join_set.spawn(
                async move { client.preproc_key_gen(request).await }
                    .instrument(tracing::Span::current()),
            );
        });

        let mut responses: Vec<SessionId> = Vec::new();
        while let Some(response) = join_set.join_next().await {
            responses
                .push(bc2wrap::deserialize_safe(&(response??.into_inner().request_id)).unwrap());
        }

        let ref_response = responses.first().unwrap();
        for response in responses.iter() {
            assert_eq!(response, ref_response);
        }

        Ok(*ref_response)
    }

    #[instrument(name = "DKG Request (BGV)", skip(self, session_id), fields(sid = ?session_id, preproc_sid = ?session_id_preproc))]
    pub async fn bgv_initiate_threshold_keygen(
        &self,
        session_id: SessionId,
        session_id_preproc: Option<SessionId>,
        threshold: u32,
        seed: Option<u64>,
    ) -> anyhow::Result<SessionId> {
        let role_assignment = bc2wrap::serialize(&self.role_assignments)?;
        let threshold_keygen_params = bc2wrap::serialize(&ThresholdKeyGenParams {
            session_id,
            session_id_preproc,
        })?;

        let mut join_set = JoinSet::new();
        self.channels.values().for_each(|channel| {
            let mut client = self.new_client(channel.clone());
            let request = ThresholdKeyGenRequest {
                role_assignment: role_assignment.to_vec(),
                threshold,
                params: threshold_keygen_params.to_vec(),
                seed,
            };

            join_set.spawn(
                async move { client.threshold_key_gen(request).await }
                    .instrument(tracing::Span::current()),
            );
        });

        let mut responses: Vec<SessionId> = Vec::new();
        while let Some(response) = join_set.join_next().await {
            responses
                .push(bc2wrap::deserialize_safe(&(response??.into_inner().request_id)).unwrap());
        }

        let ref_response = responses.first().unwrap();
        for response in responses.iter() {
            assert_eq!(response, ref_response);
        }

        Ok(*ref_response)
    }

    ///NOTE: If dkg_params.is_some(), we will actually generate a new set of keys and stored it under session_id,
    ///otherwise we try and retrieve existing keys
    #[instrument(name = "DKG-Result Request (BGV)", skip(self, session_id), fields(sid = ?session_id))]
    pub async fn bgv_initiate_threshold_keygen_result(
        &self,
        session_id: SessionId,
        gen_params: Option<bool>,
        seed: Option<u64>,
    ) -> anyhow::Result<PublicKey<LevelEll, LevelKsw, N65536>> {
        let role_assignment = bc2wrap::serialize(&self.role_assignments)?;

        let threshold_keygen_result_params = bc2wrap::serialize(&ThresholdKeyGenResultParams {
            session_id,
            gen_params: gen_params.unwrap_or(false),
        })?;

        let mut join_set = JoinSet::new();
        self.channels.values().for_each(|channel| {
            let mut client = self.new_client(channel.clone());
            let request = ThresholdKeyGenResultRequest {
                role_assignment: role_assignment.to_vec(),
                params: threshold_keygen_result_params.to_vec(),
                seed,
            };
            join_set.spawn(
                async move { client.threshold_key_gen_result(request).await }
                    .instrument(tracing::Span::current()),
            );
        });

        let mut responses = Vec::new();
        while let Some(response) = join_set.join_next().await {
            let response = response??.into_inner();
            responses.push(response.pub_keyset);
        }

        //NOTE: Cant really assert here as keys dont implement eq trait, and cant assert eq on serialized data
        //let ref_response = responses.first().unwrap();
        //for response in responses.iter() {
        //    assert_eq!(response, ref_response);
        //}
        let pub_key = responses.pop().unwrap();
        let pub_key = bc2wrap::deserialize_safe(&pub_key)?;
        Ok(pub_key)
    }

    #[instrument(name = "DDec Request (BGV)", skip(self, session_id, ctxts), fields(num_sessions = ?ctxts.len(), sid= ?session_id))]
    pub async fn bgv_initiate_threshold_decrypt(
        &self,
        session_id: SessionId,
        key_sid: SessionId,
        ctxts: Vec<LevelEllCiphertext>,
        num_ctxt_per_session: usize,
        threshold: u32,
        seed: Option<u64>,
    ) -> anyhow::Result<SessionId> {
        let role_assignment = bc2wrap::serialize(&self.role_assignments)?;
        let threshold_decrypt_params = bc2wrap::serialize(&ThresholdDecryptParams {
            session_id,
            key_sid,
            ctxts,
            num_ctxt_per_session,
        })?;

        let mut join_set = JoinSet::new();
        self.channels.values().for_each(|channel| {
            let mut client = self.new_client(channel.clone());
            let request = ThresholdDecryptRequest {
                role_assignment: role_assignment.to_vec(),
                threshold,
                params: threshold_decrypt_params.to_vec(),
                seed,
            };

            join_set.spawn(
                async move { client.threshold_decrypt(request).await }
                    .instrument(tracing::Span::current()),
            );
        });

        let mut responses: Vec<SessionId> = Vec::new();
        while let Some(response) = join_set.join_next().await {
            responses
                .push(bc2wrap::deserialize_safe(&(response??.into_inner().request_id)).unwrap());
        }

        let ref_response = responses.first().unwrap();
        for response in responses.iter() {
            assert_eq!(ref_response, response)
        }

        Ok(*ref_response)
    }

    #[instrument(name = "DDec-Result Request (BGV)", skip(self, session_id), fields(sid= ?session_id))]
    pub async fn bgv_initiate_threshold_decrypt_result(
        &self,
        session_id: SessionId,
    ) -> anyhow::Result<Vec<Vec<u32>>> {
        let mut join_set = JoinSet::new();
        let serialized_sid = bc2wrap::serialize(&session_id)?;
        self.channels.values().for_each(|channel| {
            let mut client = self.new_client(channel.clone());
            let request = ThresholdDecryptResultRequest {
                request_id: serialized_sid.to_vec(),
            };

            join_set.spawn(
                async move { client.threshold_decrypt_result(request).await }
                    .instrument(tracing::Span::current()),
            );
        });

        let mut responses: Vec<Vec<Vec<u32>>> = Vec::new();
        while let Some(response) = join_set.join_next().await {
            responses.push(bc2wrap::deserialize_safe(
                &(response??.into_inner().plaintext),
            )?);
        }

        let ref_response = responses.first().unwrap();
        for response in responses.iter() {
            assert_eq!(ref_response, response)
        }

        Ok(ref_response.clone())
    }
}
