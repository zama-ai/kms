use crate::{
    dummy_domain, keygen::check_standard_keyset_ext_signature,
    s3_operations::fetch_public_elements, CmdConfig, CoreClientConfig, CoreConf, DigestKeySet,
    NewEpochParameters, PreviousEpochParameters, SLEEP_TIME_BETWEEN_REQUESTS_MS,
};
use kms_grpc::{
    identifiers::EpochId,
    kms::v1::{DestroyMpcEpochRequest, FheParameter, KeyDigest, KeyInfo, PreviousEpochInfo},
    kms_service::v1::core_service_endpoint_client::CoreServiceEndpointClient,
    rpc_types::{alloy_to_protobuf_domain, PubDataType},
    RequestId,
};
use kms_lib::{
    client::client_wasm::Client,
    util::key_setup::test_tools::{load_material_from_pub_storage, load_pk_from_pub_storage},
};
use std::{collections::HashMap, path::Path};
use tokio::task::JoinSet;
use tonic::transport::Channel;

impl PreviousEpochParameters {
    pub(crate) fn convert_to_grpc(
        &self,
        fhe_params: FheParameter,
    ) -> anyhow::Result<PreviousEpochInfo> {
        let mut keys_info = Vec::with_capacity(self.previous_keys.len());
        for previous_key_info in &self.previous_keys {
            let digest = match &previous_key_info.key_digest {
                DigestKeySet::NonCompressedKeySet(server_key_digest, public_key_digest) => {
                    vec![
                        KeyDigest {
                            key_type: PubDataType::ServerKey.to_string(),
                            digest: hex::decode(server_key_digest).map_err(|e| {
                                anyhow::anyhow!(
                                    "Unable to decode the provided server key digest {:?}: {:?}",
                                    server_key_digest,
                                    e
                                )
                            })?,
                        },
                        KeyDigest {
                            key_type: PubDataType::PublicKey.to_string(),
                            digest: hex::decode(public_key_digest).map_err(|e| {
                                anyhow::anyhow!(
                                    "Unable to decode the provided public key digest {:?}: {:?}",
                                    public_key_digest,
                                    e
                                )
                            })?,
                        },
                    ]
                }
                DigestKeySet::CompressedKeySet(xof_key_digest) => vec![KeyDigest {
                    key_type: PubDataType::CompressedXofKeySet.to_string(),
                    digest: hex::decode(xof_key_digest).map_err(|e| {
                        anyhow::anyhow!(
                            "Unable to decode the provided xof key digest {:?}: {:?}",
                            xof_key_digest,
                            e
                        )
                    })?,
                }],
            };

            keys_info.push(KeyInfo {
                key_id: Some(previous_key_info.key_id.into()),
                preproc_id: Some(previous_key_info.preproc_id.into()),
                key_parameters: fhe_params.into(),
                key_digests: digest,
            });
        }

        let mut crs_info = Vec::with_capacity(self.previous_crs.len());
        for previous_crs_info in &self.previous_crs {
            crs_info.push(kms_grpc::kms::v1::CrsInfo {
                crs_id: Some(previous_crs_info.crs_id.into()),
                crs_digest: hex::decode(&previous_crs_info.digest).map_err(|e| {
                    anyhow::anyhow!(
                        "Unable to decode the provided crs digest {:?}: {:?}",
                        previous_crs_info.digest,
                        e
                    )
                })?,
                domain: Some(alloy_to_protobuf_domain(&dummy_domain())?),
            });
        }

        let resp = PreviousEpochInfo {
            context_id: Some(self.context_id.into()),
            epoch_id: Some(self.epoch_id.into()),
            keys_info,
            crs_info,
        };

        println!("Constructed PreviousEpochInfo for gRPC request: {:?}", resp);
        Ok(resp)
    }
}

#[allow(clippy::too_many_arguments)]
// NOTE: The new context must already exist !
pub(crate) async fn do_new_epoch(
    internal_client: &mut Client,
    core_endpoints: &HashMap<CoreConf, CoreServiceEndpointClient<Channel>>,
    cmd_conf: &CmdConfig,
    cc_conf: &CoreClientConfig,
    destination_prefix: &Path,
    kms_addrs: &[alloy_primitives::Address],
    num_parties: usize,
    fhe_params: FheParameter,
    new_epoch_params: NewEpochParameters,
) -> anyhow::Result<EpochId> {
    tracing::info!("Starting new epoch creation...");
    tracing::info!("CONFIG IS : {:?}", cc_conf.cores);
    let max_iter = cmd_conf.max_iter;

    let (new_epoch_id, new_context_id) = (
        new_epoch_params.new_epoch_id,
        new_epoch_params.new_context_id,
    );
    let previous_epoch_grpc = new_epoch_params
        .previous_epoch_params
        .as_ref()
        .map(|previous_epoch| previous_epoch.convert_to_grpc(fhe_params))
        .transpose()?;
    let domain = if new_epoch_params.previous_epoch_params.is_some() {
        Some(dummy_domain())
    } else {
        None
    };
    let request = internal_client.new_epoch_request(
        &new_context_id,
        &new_epoch_id,
        previous_epoch_grpc,
        domain.as_ref(),
    )?;

    // Send the request
    let mut req_tasks = JoinSet::new();
    for (core_conf, ce) in core_endpoints.iter() {
        let req_cloned = request.clone();
        let mut cur_client = ce.clone();
        let core_conf = core_conf.clone();
        req_tasks.spawn(async move {
            (
                core_conf,
                cur_client
                    .new_mpc_epoch(tonic::Request::new(req_cloned))
                    .await,
            )
        });
    }

    let mut results = Vec::new();
    while let Some(inner) = req_tasks.join_next().await {
        let (core_conf, result) = inner?;
        let result = result?.into_inner();
        results.push((core_conf, result));
    }

    if cmd_conf.expect_all_responses {
        anyhow::ensure!(
            results.len() == num_parties,
            "Expected {} epoch responses but got {}",
            num_parties,
            results.len()
        );
    }

    // In all cases poll the result endpoint as PRSS init is now non-blocking
    // Poll the result endpoint
    let mut response_tasks = JoinSet::new();
    for (core_conf, ce) in core_endpoints.iter() {
        let mut cur_client = ce.clone();

        let core_conf = core_conf.clone();
        response_tasks.spawn(async move {
            let response_request: tonic::Request<kms_grpc::kms::v1::RequestId> =
                tonic::Request::new(new_epoch_id.into());
            tokio::time::sleep(tokio::time::Duration::from_millis(
                SLEEP_TIME_BETWEEN_REQUESTS_MS,
            ))
            .await;
            let mut response = cur_client.get_epoch_result(response_request).await;

            let mut ctr = 0_usize;
            while response.is_err()
                && response.as_ref().unwrap_err().code() == tonic::Code::Unavailable
            {
                tokio::time::sleep(tokio::time::Duration::from_millis(
                    SLEEP_TIME_BETWEEN_REQUESTS_MS,
                ))
                .await;
                let response_request: tonic::Request<kms_grpc::kms::v1::RequestId> =
                    tonic::Request::new(new_epoch_id.into());
                response = cur_client.get_epoch_result(response_request).await;
                ctr += 1;
                if ctr >= max_iter {
                    break;
                }
            }

            (core_conf, response)
        });
    }

    if let Some(previous_epoch) = new_epoch_params.previous_epoch_params {
        let (expected_key_ids, expected_preproc_ids): (
            Vec<kms_grpc::kms::v1::RequestId>,
            Vec<kms_grpc::kms::v1::RequestId>,
        ) = previous_epoch
            .previous_keys
            .iter()
            .map(|k| (k.key_id.into(), k.preproc_id.into()))
            .unzip();

        let mut response_vec = Vec::new();
        while let Some(response) = response_tasks.join_next().await {
            let (core_conf, response) = response?;
            let response = response?;
            let resp = response.into_inner();

            let mut resp_key_ids = Vec::new();
            let mut resp_preproc_ids = Vec::new();
            for k in &resp.reshare_responses {
                resp_key_ids.push(
                    k.request_id
                        .as_ref()
                        .ok_or_else(|| anyhow::anyhow!("Key ID must be set in resharing response"))?
                        .clone(),
                );
                resp_preproc_ids.push(
                    k.preprocessing_id
                        .as_ref()
                        .ok_or_else(|| {
                            anyhow::anyhow!("Preprocessing ID must be set in resharing response")
                        })?
                        .clone(),
                );
            }

            anyhow::ensure!(
                resp_key_ids == expected_key_ids,
                "Resharing response did not contain the expected key IDs! Got {:?}, but expected {:?}",
                resp_key_ids, expected_key_ids
            );
            anyhow::ensure!(
                resp_preproc_ids == expected_preproc_ids,
                "Resharing response did not contain the expected preprocessing IDs! Got {:?}, but expected {:?}",
                resp_preproc_ids, expected_preproc_ids
            );
            response_vec.push((core_conf, resp));
        }
        let key_types = vec![PubDataType::PublicKey, PubDataType::ServerKey];

        for (key_id, preproc_id) in expected_key_ids.into_iter().zip(expected_preproc_ids) {
            // We try to download all because all parties needed to respond for a successful resharing
            let key_id: RequestId = key_id.try_into().map_err(|e| {
                anyhow::anyhow!("Failed to convert grpc RequestId to internal RequestId: {e}")
            })?;

            let party_confs_successful = fetch_public_elements(
                &key_id.to_string(),
                &key_types,
                cc_conf,
                destination_prefix,
                true,
            )
            .await?;

            anyhow::ensure!(
                party_confs_successful.len() == num_parties,
                "Did not fetch keys from all parties after resharing! Got {}, expected {}",
                party_confs_successful.len(),
                num_parties
            );

            // We just checked that we have num_parties of fetched configurations
            let first_party_id = party_confs_successful.first()
                .expect("unexpected error because we have previously checked that the array has length of num_parties").party_id;
            let pub_storage_prefix = Some(cc_conf.cores[first_party_id - 1].object_folder.as_str());

            let public_key =
                load_pk_from_pub_storage(Some(destination_prefix), &key_id, pub_storage_prefix);
            let server_key = load_material_from_pub_storage(
                Some(destination_prefix),
                &key_id,
                PubDataType::ServerKey,
                pub_storage_prefix,
            );

            let (public_key, server_key) = tokio::join!(public_key, server_key);

            let preproc_id: RequestId = preproc_id.try_into().map_err(|e| {
                anyhow::anyhow!("Failed to convert grpc RequestId to internal RequestId: {e}")
            })?;

            for (_, response) in response_vec.iter() {
                let key_id_proto: kms_grpc::kms::v1::RequestId = key_id.into();
                let preproc_id_proto: kms_grpc::kms::v1::RequestId = preproc_id.into();
                let signature = response
                    .reshare_responses
                    .iter()
                    .find(|r| {
                        r.request_id.as_ref() == Some(&key_id_proto)
                            && r.preprocessing_id.as_ref() == Some(&preproc_id_proto)
                    })
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "No resharing response found for key_id={} and preproc_id={}",
                            key_id,
                            preproc_id
                        )
                    })?
                    .external_signature
                    .clone();

                check_standard_keyset_ext_signature(
                    &public_key,
                    &server_key,
                    &preproc_id,
                    &key_id,
                    &signature,
                    &dummy_domain(),
                    vec![], // TODO RFC005, once extra data is added to request we need it here to verify the signature
                    kms_addrs,
                )?;
            }
        }
    } else {
        // If it was just a PRSS init simply make sure all is ok
        while let Some(response) = response_tasks.join_next().await {
            let (_core_conf, response) = response?;
            let _response = response?;
        }
    }
    Ok(new_epoch_id)
}

pub(crate) async fn do_destroy_mpc_epoch(
    core_endpoints: &HashMap<CoreConf, CoreServiceEndpointClient<Channel>>,
    epoch_id: &EpochId,
) -> anyhow::Result<()> {
    let mut req_tasks = JoinSet::new();
    for (_party_id, ce) in core_endpoints.iter() {
        let mut cur_client = ce.clone();
        let epoch_cloned = (*epoch_id).into();
        req_tasks.spawn(async move {
            cur_client
                .destroy_mpc_epoch(DestroyMpcEpochRequest {
                    epoch_id: Some(epoch_cloned),
                })
                .await
        });
    }
    while let Some(inner) = req_tasks.join_next().await {
        let _ = inner??;
    }

    Ok(())
}
