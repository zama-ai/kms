use std::collections::HashMap;

use kms_grpc::{
    identifiers::ContextId,
    kms::v1::{DestroyMpcContextRequest, NewMpcContextRequest},
    kms_service::v1::core_service_endpoint_client::CoreServiceEndpointClient,
};
#[cfg(feature = "testing")]
use kms_lib::{
    conf::{init_conf, CoreConfig},
    engine::context::{NodeInfo, SoftwareVersion},
};
use kms_lib::{consts::SAFE_SER_SIZE_LIMIT, engine::context::ContextInfo};
use tfhe::safe_serialization::safe_deserialize;
use tokio::task::JoinSet;
use tonic::transport::Channel;

use crate::CoreConf;
#[cfg(feature = "testing")]
use crate::{
    s3_operations::{fetch_kms_signing_keys, fetch_kms_verification_keys},
    CoreClientConfig,
};

#[cfg(feature = "testing")]
pub async fn create_test_context_info_from_core_config(
    context_id: ContextId,
    sim_conf: &CoreClientConfig,
) -> anyhow::Result<ContextInfo> {
    // first download the verification and signing keys from all parties
    let verification_keys = fetch_kms_verification_keys(sim_conf).await?;
    let signing_keys = fetch_kms_signing_keys(sim_conf).await?;

    // load the compose_x.toml files, because we need the MPC identities and dummy pcr values
    let mut pcr_values = HashMap::new();
    let mut mpc_nodes = vec![];
    let mut thresholds = vec![];
    for c in sim_conf.cores.iter() {
        let config_path = c
            .config_path
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Core config path not set for core {}", c.party_id))?;
        let core_config: CoreConfig = init_conf(config_path.to_str().unwrap()).unwrap();

        // For testing, we only support the mocked trusted release mode
        // this requires the "mock_enclave = true" attribute in the kms-server config toml files.
        let threshold_config = core_config.threshold.clone().unwrap();
        match threshold_config.tls.unwrap() {
            kms_lib::conf::threshold::TlsConf::Auto {
                eif_signing_cert: _,
                trusted_releases,
                ignore_aws_ca_chain: _,
                attest_private_vault_root_key: _,
                renew_slack_after_expiration: _,
                renew_fail_retry_timeout: _,
            } => {
                pcr_values.insert(c.party_id, trusted_releases);
            }
            _ => {
                return Err(anyhow::anyhow!(
                    "Core config TLS not in full auto mode with PCR values for core {}",
                    c.party_id
                ));
            }
        }

        // this assumes that the peer list is ordered by party ID
        let peer = &threshold_config.peers.unwrap()[c.party_id - 1];
        let (role, identity) = peer.into_role_identity();
        if let Some(initial_id) = threshold_config.my_id {
            if role.one_based() != initial_id {
                // this might be a misconfiguration, but useful for testing
                // because threshold_config.my_id may be used as a storage prefix that
                // must be different from the party ID in the peerlist to avoid collision
                tracing::warn!(
                    "Mismatched party ID in core config for core {}: role ID {}, my_id {}",
                    c.party_id,
                    role.one_based(),
                    initial_id
                );
            }
        }

        let verification_key = verification_keys.get(&role.one_based()).ok_or_else(|| {
            anyhow::anyhow!(
                "No verification key found for party ID {}",
                role.one_based()
            )
        })?;
        let sk = signing_keys.get(&role.one_based()).ok_or_else(|| {
            anyhow::anyhow!("No signing key found for party ID {}", role.one_based())
        })?;

        let mpc_identity = identity.mpc_identity();
        let (_ca_cert_ki, ca_cert) = threshold_fhe::tls_certs::create_ca_cert_from_signing_key(
            mpc_identity.as_ref(),
            true,
            #[allow(deprecated)]
            sk.sk(),
        )?;

        // build the s3 endpoint URL
        let (s3_endpoint, prefix) =
            match (core_config.public_vault.as_ref(), core_config.aws.as_ref()) {
                (Some(public_vault), Some(aws_conf)) => {
                    let (bucket, prefix) = match &public_vault.storage {
                        kms_lib::conf::Storage::S3(s3_storage) => {
                            (&s3_storage.bucket, s3_storage.prefix.clone())
                        }
                        _ => {
                            return Err(anyhow::anyhow!(
                                "Public vault storage is not S3 for core {}",
                                c.party_id
                            ));
                        }
                    };

                    let s3_endpoint = aws_conf.s3_endpoint.as_ref().ok_or(anyhow::anyhow!(
                        "No public S3 endpoint found for core {}",
                        c.party_id
                    ))?;

                    // we try to detect whether the s3 endpoint is a custom one or a standard AWS one
                    let s3_endpoint = if s3_endpoint.as_str().contains("dev-s3-mock:9000") {
                        s3_endpoint.to_string()
                    } else {
                        // if it's the s3 endpoint, we need to build the full bucket URL
                        format!("https://{}.s3.{}.amazonaws.com", bucket, aws_conf.region)
                    };
                    (s3_endpoint, prefix)
                }
                _ => {
                    return Err(anyhow::anyhow!(
                        "No public S3 endpoint or AWS config found for core {}",
                        c.party_id
                    ));
                }
            };

        // sanity check that the storage prefix matches object_folder
        if Some(c.object_folder.as_str()) != prefix.as_deref() {
            return Err(anyhow::anyhow!(
                "Storage prefix mismatch for core {}: config object_folder {:?}, public vault prefix {:?}",
                c.party_id,
                c.object_folder,
                prefix
            ));
        }

        mpc_nodes.push(NodeInfo {
            mpc_identity: mpc_identity.to_string(),
            party_id: role.one_based() as u32,
            verification_key: Some(verification_key.clone()),
            external_url: format!("https://{}:{}", identity.hostname(), identity.port()),
            ca_cert: Some(ca_cert.pem().as_bytes().to_vec()),
            public_storage_url: s3_endpoint,
            public_storage_prefix: prefix,
            extra_verification_keys: vec![],
        });

        thresholds.push(threshold_config.threshold);
    }

    // check that all the pcr values are the same
    let first_pcr_values = pcr_values
        .values()
        .next()
        .ok_or_else(|| anyhow::anyhow!("No PCR values found"))?;
    for (party_id, pcrs) in pcr_values.iter() {
        if pcrs != first_pcr_values {
            return Err(anyhow::anyhow!(
                "PCR values do not match between parties. Party {} has {:?}, expected {:?}",
                party_id,
                pcrs,
                first_pcr_values
            ));
        }
    }

    // make sure all the threshold are the same
    let threshold = thresholds
        .first()
        .ok_or_else(|| anyhow::anyhow!("No thresholds found when creating new MPC context"))?;
    if !thresholds.iter().all(|x| x == threshold) {
        return Err(anyhow::anyhow!(
            "Thresholds do not match between parties when creating new MPC context"
        ));
    }

    let new_context = ContextInfo {
        mpc_nodes,
        context_id,
        software_version: SoftwareVersion::current(),
        threshold: *threshold as u32,
        pcr_values: first_pcr_values.to_vec(),
    };
    Ok(new_context)
}

pub(crate) async fn do_new_mpc_context(
    core_endpoints: &HashMap<CoreConf, CoreServiceEndpointClient<Channel>>,
    context_path: &std::path::Path,
) -> anyhow::Result<ContextId> {
    // note that we use the BufReader from std instead of tokio
    // because the one from tokio does not implement std::io::Read
    let file = std::fs::File::open(context_path)?;
    let mut buf_reader = std::io::BufReader::new(file);

    let new_context: ContextInfo = safe_deserialize(&mut buf_reader, SAFE_SER_SIZE_LIMIT)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize context info from file: {}", e))?;
    let context_id = new_context.context_id;

    let mut req_tasks = JoinSet::new();
    for (_party_id, ce) in core_endpoints.iter() {
        let mut cur_client = ce.clone();
        let new_context_cloned = new_context.clone();
        req_tasks.spawn(async move {
            cur_client
                .new_mpc_context(tonic::Request::new(NewMpcContextRequest {
                    new_context: Some(new_context_cloned.try_into().unwrap()),
                }))
                .await
        });
    }
    while let Some(inner) = req_tasks.join_next().await {
        let _ = inner??;
    }

    Ok(context_id)
}

pub(crate) async fn do_destroy_mpc_context(
    core_endpoints: &HashMap<CoreConf, CoreServiceEndpointClient<Channel>>,
    context_id: &ContextId,
) -> anyhow::Result<()> {
    let mut req_tasks = JoinSet::new();
    for (_party_id, ce) in core_endpoints.iter() {
        let mut cur_client = ce.clone();
        let context_cloned = (*context_id).into();
        req_tasks.spawn(async move {
            cur_client
                .destroy_mpc_context(DestroyMpcContextRequest {
                    context_id: Some(context_cloned),
                })
                .await
        });
    }
    while let Some(inner) = req_tasks.join_next().await {
        let _ = inner??;
    }

    Ok(())
}
