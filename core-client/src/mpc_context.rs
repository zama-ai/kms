use std::collections::HashMap;

use aes_prng::AesRng;
use kms_grpc::{
    identifiers::ContextId, kms::v1::NewKmsContextRequest,
    kms_service::v1::core_service_endpoint_client::CoreServiceEndpointClient,
};
use kms_lib::{
    conf::{init_conf, CoreConfig},
    engine::context::{ContextInfo, NodeInfo, SoftwareVersion},
};
use tokio::task::JoinSet;
use tonic::transport::Channel;

use crate::{
    s3_operations::{fetch_kms_signing_keys, fetch_kms_verification_keys},
    CoreClientConfig,
};

pub(crate) async fn do_new_mpc_context(
    core_endpoints: &HashMap<u32, CoreServiceEndpointClient<Channel>>,
    rng: &mut AesRng,
    sim_conf: &CoreClientConfig,
) -> anyhow::Result<ContextId> {
    // first download the verification and signing keys from all parties
    let verification_keys = fetch_kms_verification_keys(sim_conf).await?;
    let signing_keys = fetch_kms_signing_keys(sim_conf).await?;

    // load the compose_x.toml files, because we need the MPC identities and dummy pcr values
    let mut pcr_values = HashMap::new();
    let mut kms_nodes = vec![];
    let mut thresholds = vec![];
    for c in sim_conf.cores.iter() {
        let config_path = c
            .config_path
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Core config path not set for core {}", c.party_id))?;
        let core_config: CoreConfig = init_conf(config_path.to_str().unwrap()).unwrap();

        // at the moment we only support the mocked trusted release mode
        let threshold_config = core_config.threshold.clone().unwrap();
        match threshold_config.tls.unwrap() {
            kms_lib::conf::threshold::TlsConf::FullAuto { trusted_releases } => {
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
        assert_eq!(role.one_based(), threshold_config.my_id);

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

        kms_nodes.push(NodeInfo {
            mpc_identity: mpc_identity.to_string(),
            party_id: role.one_based() as u32,
            verification_key: Some(verification_key.clone()),
            external_url: format!("https://{}:{}", identity.hostname(), identity.port()),
            ca_cert: Some(ca_cert.pem().as_bytes().to_vec()),
            public_storage_url: c.s3_endpoint.clone(),
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

    let context_id = ContextId::new_random(rng);
    let mut req_tasks = JoinSet::new();
    let new_context = ContextInfo {
        kms_nodes,
        context_id,
        software_version: SoftwareVersion::current(),
        threshold: *threshold as u32,
        pcr_values: first_pcr_values.to_vec(),
    };
    for (_party_id, ce) in core_endpoints.iter() {
        let mut cur_client = ce.clone();
        let new_context_cloned = new_context.clone();
        req_tasks.spawn(async move {
            cur_client
                .new_kms_context(tonic::Request::new(NewKmsContextRequest {
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
