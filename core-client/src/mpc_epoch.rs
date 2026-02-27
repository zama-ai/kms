use crate::{
    dummy_domain, keygen::check_standard_keyset_ext_signature,
    s3_operations::fetch_public_elements, CmdConfig, CoreClientConfig, CoreConf,
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
use tfhe::ServerKey;
use tokio::task::JoinSet;
use tonic::transport::Channel;

impl PreviousEpochParameters {
    pub(crate) fn convert_to_grpc(&self, fhe_params: FheParameter) -> PreviousEpochInfo {
        let expected_num_keys = self.keys_id.len();
        assert_eq!(self.server_keys_digest.len(), expected_num_keys);
        assert_eq!(self.public_keys_digest.len(), expected_num_keys);
        assert_eq!(self.preprocs_id.len(), expected_num_keys);

        let key_digests = self
            .server_keys_digest
            .iter()
            .zip(self.public_keys_digest.iter())
            .map(|(server_digest, public_digest)| {
                vec![
                    KeyDigest {
                        key_type: PubDataType::ServerKey.to_string(),
                        digest: hex::decode(server_digest).unwrap(),
                    },
                    KeyDigest {
                        key_type: PubDataType::PublicKey.to_string(),
                        digest: hex::decode(public_digest).unwrap(),
                    },
                ]
            })
            .collect::<Vec<_>>();

        let keys_info = self
            .keys_id
            .iter()
            .zip(self.preprocs_id.iter())
            .zip(key_digests)
            .map(|((key_id, preproc_id), key_digests)| KeyInfo {
                key_id: Some((*key_id).into()),
                preproc_id: Some((*preproc_id).into()),
                key_parameters: fhe_params.into(),
                key_digests,
                domain: Some(alloy_to_protobuf_domain(&dummy_domain()).unwrap()),
            })
            .collect::<Vec<_>>();

        PreviousEpochInfo {
            context_id: Some(self.context_id.into()),
            epoch_id: Some(self.epoch_id.into()),
            keys_info,
        }
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
    let request = internal_client.new_epoch_request(
        &new_context_id,
        &new_epoch_id,
        new_epoch_params
            .previous_epoch_params
            .as_ref()
            .map(|previous_epoch| previous_epoch.convert_to_grpc(fhe_params)),
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
        assert_eq!(results.len(), num_parties);
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
        let expected_key_ids = previous_epoch
            .keys_id
            .iter()
            .map(|k| (*k).into())
            .collect::<Vec<_>>();
        let expected_preproc_ids = previous_epoch
            .preprocs_id
            .iter()
            .map(|p| (*p).into())
            .collect::<Vec<_>>();

        let mut response_vec = Vec::new();
        while let Some(response) = response_tasks.join_next().await {
            let (core_conf, response) = response?;
            let response = response?;
            let resp = response.into_inner();

            let resp_key_ids = resp
                .reshare_responses
                .iter()
                .map(|k| k.key_id.clone().unwrap())
                .collect::<Vec<_>>();
            assert_eq!(resp_key_ids, expected_key_ids);

            let resp_preproc_ids = resp
                .reshare_responses
                .iter()
                .map(|k| k.preprocessing_id.clone().unwrap())
                .collect::<Vec<_>>();
            assert_eq!(resp_preproc_ids, expected_preproc_ids,);
            response_vec.push((core_conf, resp));
        }
        let key_types = vec![PubDataType::PublicKey, PubDataType::ServerKey];

        for (key_id, preproc_id) in expected_key_ids
            .into_iter()
            .zip(expected_preproc_ids.into_iter())
        {
            // We try to download all because all parties needed to respond for a successful resharing
            let key_id: RequestId = key_id.try_into().unwrap();

            let party_confs = fetch_public_elements(
                &key_id.to_string(),
                &key_types,
                cc_conf,
                destination_prefix,
                true,
            )
            .await
            .unwrap();

            assert_eq!(
                party_confs.len(),
                num_parties,
                "Did not fetch keys from all parties after resharing!"
            );

            let storage_prefix = Some(
                cc_conf
                    .cores
                    .iter()
                    .find(|c| c == &&party_confs[0])
                    .expect("party ID not found in config")
                    .object_folder
                    .as_str(),
            );

            let public_key =
                load_pk_from_pub_storage(Some(destination_prefix), &key_id, storage_prefix).await;
            let server_key: ServerKey = load_material_from_pub_storage(
                Some(destination_prefix),
                &key_id,
                PubDataType::ServerKey,
                storage_prefix,
            )
            .await;

            let preproc_id: RequestId = preproc_id.try_into().unwrap();
            for response in response_vec.iter() {
                let signature = response
                    .1
                    .reshare_responses
                    .iter()
                    .find(|r| {
                        r.key_id.as_ref().unwrap() == &key_id.into()
                            && r.preprocessing_id.as_ref().unwrap() == &preproc_id.into()
                    })
                    .expect("No resharing response found for the key and preprocessing ID")
                    .external_signature
                    .clone();

                check_standard_keyset_ext_signature(
                    &public_key,
                    &server_key,
                    &preproc_id,
                    &key_id,
                    &signature,
                    &dummy_domain(),
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
