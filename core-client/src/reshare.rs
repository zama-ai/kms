use crate::{
    dummy_domain, keygen::check_standard_keyset_ext_signature,
    s3_operations::fetch_public_elements, CmdConfig, CoreClientConfig, CoreConf,
    PreviousEpochParameters, SLEEP_TIME_BETWEEN_REQUESTS_MS,
};
use aes_prng::AesRng;
use kms_grpc::{
    identifiers::EpochId,
    kms::v1::{FheParameter, KeyDigest, PreviousEpochInfo},
    kms_service::v1::core_service_endpoint_client::CoreServiceEndpointClient,
    rpc_types::{alloy_to_protobuf_domain, PubDataType},
    ContextId, RequestId,
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
        let key_digests = vec![
            (KeyDigest {
                key_type: PubDataType::ServerKey.to_string(),
                digest: hex::decode(&self.server_key_digest).unwrap(),
            }),
            (KeyDigest {
                key_type: PubDataType::PublicKey.to_string(),
                digest: hex::decode(&self.public_key_digest).unwrap(),
            }),
        ];

        PreviousEpochInfo {
            key_id: Some(self.key_id.into()),
            preproc_id: Some(self.preproc_id.into()),
            context_id: Some(self.context_id.into()),
            epoch_id: Some(self.epoch_id.into()),
            key_parameters: fhe_params.into(),
            key_digests,
            domain: Some(alloy_to_protobuf_domain(&dummy_domain()).unwrap()),
        }
    }
}

#[allow(clippy::too_many_arguments)]
// NOTE: The new context must already exist !
pub(crate) async fn do_new_epoch(
    internal_client: &mut Client,
    core_endpoints: &HashMap<CoreConf, CoreServiceEndpointClient<Channel>>,
    rng: &mut AesRng,
    cmd_conf: &CmdConfig,
    cc_conf: &CoreClientConfig,
    destination_prefix: &Path,
    kms_addrs: &[alloy_primitives::Address],
    num_parties: usize,
    new_context_id: ContextId,
    new_epoch_id: EpochId,
    previous_epoch: Option<PreviousEpochInfo>,
) -> anyhow::Result<EpochId> {
    println!("Starting new epoch creation...");
    println!("CONFIG IS : {:?}", cc_conf.cores);
    let max_iter = cmd_conf.max_iter;
    let request_id = RequestId::new_random(rng);

    let request = internal_client.new_epoch_request(
        &request_id,
        &new_context_id,
        &new_epoch_id,
        previous_epoch.clone(),
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

    // We need to wait for all responses since an epoch creation  is only successful if _all_ parties respond.
    assert_eq!(results.len(), num_parties);

    if let Some(previous_epoch) = previous_epoch {
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

        let mut response_vec = Vec::new();
        while let Some(response) = response_tasks.join_next().await {
            let (core_conf, response) = response?;
            let response = response?;
            let resp = response.into_inner();
            assert_eq!(resp.request_id, Some(new_epoch_id.into()));
            assert_eq!(resp.key_id, previous_epoch.key_id);
            assert_eq!(resp.preprocessing_id, previous_epoch.preproc_id);
            response_vec.push((core_conf, resp));
        }

        let key_types = vec![
            PubDataType::PublicKey,
            PubDataType::PublicKeyMetadata,
            PubDataType::ServerKey,
        ];

        // We try to download all because all parties needed to respond for a successful resharing
        let element_id: RequestId = previous_epoch.key_id.clone().unwrap().try_into().unwrap();

        let party_confs = fetch_public_elements(
            &element_id.to_string(),
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

        let key_id = previous_epoch.key_id.unwrap().try_into().unwrap();
        let preproc_id = previous_epoch.preproc_id.unwrap().try_into().unwrap();
        let public_key =
            load_pk_from_pub_storage(Some(destination_prefix), &key_id, storage_prefix).await;
        let server_key: ServerKey = load_material_from_pub_storage(
            Some(destination_prefix),
            &key_id,
            PubDataType::ServerKey,
            storage_prefix,
        )
        .await;

        for response in response_vec {
            check_standard_keyset_ext_signature(
                &public_key,
                &server_key,
                &preproc_id,
                &key_id,
                &response.1.external_signature,
                &dummy_domain(),
                kms_addrs,
            )?;
        }
    };
    Ok(new_epoch_id)
}
