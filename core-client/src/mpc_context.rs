use alloy_sol_types::Eip712Domain;
use kms_grpc::{
    identifiers::{ContextId, EpochId},
    kms::v1::{DestroyMpcContextResponse, NewMpcContextRequest},
    kms_service::v1::core_service_endpoint_client::CoreServiceEndpointClient,
    solidity_types::ContextDestructionVerification,
};
#[cfg(feature = "testing")]
use kms_lib::{
    conf::{CoreConfig, init_conf},
    engine::context::{NodeInfo, SchemeDigests, SoftwareVersion},
};
use kms_lib::engine::base::{DSEP_DESTROY_CONTEXT, DestroyMpcContextPayload};
use kms_lib::{consts::SAFE_SER_SIZE_LIMIT, engine::context::ContextInfo};
use std::collections::{HashMap, HashSet};
use tfhe::safe_serialization::safe_deserialize;
use tokio::task::JoinSet;
use tonic::transport::Channel;

use crate::{CoreClientConfig, CoreConf};
#[cfg(feature = "testing")]
use crate::s3_operations::{fetch_kms_signing_keys, fetch_kms_verification_keys};
use kms_lib::client::client_wasm::Client;

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
        let core_config: CoreConfig = init_conf(
            config_path
                .to_str()
                .expect("Config path to be a valid UTF-8"),
        )
        .map_err(|e| anyhow::anyhow!("Failed to init config due to error: {e}"))
        .unwrap();

        // For testing, we only support the mocked trusted release mode
        // this requires the "mock_enclave = true" attribute in the kms-server config toml files.
        let threshold_config = core_config
            .threshold
            .clone()
            .ok_or_else(|| anyhow::anyhow!("Threshold config not set for core {}", c.party_id))?;
        match threshold_config
            .tls
            .ok_or_else(|| anyhow::anyhow!("TLS config not set for core {}", c.party_id))?
        {
            kms_lib::conf::threshold::TlsConf::Auto {
                eif_signing_cert: _,
                trusted_releases,
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
        let peers = threshold_config
            .peers
            .ok_or_else(|| anyhow::anyhow!("Peers not set for core {}", c.party_id))?;
        let peer = peers.get(c.party_id - 1).ok_or_else(|| {
            anyhow::anyhow!(
                "Peer index {} out of bounds (peers len: {}) for core {}",
                c.party_id - 1,
                peers.len(),
                c.party_id
            )
        })?;
        let (role, identity) = peer.into_role_identity();
        if let Some(initial_id) = threshold_config.my_id
            && role.one_based() != initial_id
        {
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

        let verification_key = verification_keys.get(&role.one_based()).ok_or_else(|| {
            anyhow::anyhow!(
                "No verification key found for party ID {}",
                role.one_based()
            )
        })?;
        let sk = signing_keys.get(&role.one_based()).ok_or_else(|| {
            anyhow::anyhow!("No signing key found for party ID {}", role.one_based())
        })?;
        let sk_der = sk.to_pkcs8_der()?;
        let ca_keypair = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(
            &sk_der.as_slice().into(),
            &rcgen::PKCS_ECDSA_P256K1_SHA256,
        )?;

        let mpc_identity = identity.mpc_identity();
        let (_ca_cert_ki, ca_cert, _ca_cert_params) =
            threshold_networking::tls_certs::create_selfsigned_cert_from_keypair(
                mpc_identity.as_ref(),
                true,
                true,
                &ca_keypair,
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

                    let s3_endpoint = aws_conf.s3_endpoint.as_ref().ok_or_else(|| {
                        anyhow::anyhow!("No public S3 endpoint found for core {}", c.party_id)
                    })?;

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
            external_url: format!("https://{}:{}", identity.hostname(), identity.port()),
            ca_cert: Some(ca_cert.pem().as_bytes().to_vec()),
            public_storage_url: s3_endpoint,
            public_storage_prefix: prefix,
            extra_signer_addresses: vec![],
            scheme_digests: SchemeDigests::from_ecdsa_verification_key(verification_key),
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
        software_version: SoftwareVersion::current()?,
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
    for ce in core_endpoints.values() {
        let mut cur_client = ce.clone();
        let new_context_cloned = new_context.clone();
        req_tasks.spawn(async move {
            cur_client
                .new_mpc_context(tonic::Request::new(NewMpcContextRequest {
                    new_context: Some(new_context_cloned.try_into().map_err(|e| {
                        tonic::Status::internal(format!(
                            "Failed to convert context info to proto: {e}"
                        ))
                    })?),
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
    internal_client: &mut Client,
    core_endpoints: &HashMap<CoreConf, CoreServiceEndpointClient<Channel>>,
    cc_conf: &CoreClientConfig,
    context_id: &ContextId,
) -> anyhow::Result<()> {
    let domain = cc_conf.default_domain()?;
    let request = internal_client.destroy_mpc_context_request(context_id, &domain)?;

    let mut req_tasks = JoinSet::new();
    for ce in core_endpoints.values() {
        let mut cur_client = ce.clone();
        let req_cloned = request.clone();
        req_tasks.spawn(async move { cur_client.destroy_mpc_context(req_cloned).await });
    }
    let mut signers = HashSet::new();
    while let Some(inner) = req_tasks.join_next().await {
        let response = inner??.into_inner();
        let (party_id, _destroyed_epochs) = check_destroy_context_response(
            internal_client,
            &response,
            context_id,
            &request.extra_data,
            &domain,
        )?;
        anyhow::ensure!(
            signers.insert(party_id),
            "party {party_id} confirmed the destruction of context {context_id} more than once"
        );
    }

    Ok(())
}

/// Check that `response` confirms the destruction of `context_id` with `extra_data`, signed under
/// every scheme `internal_client` requests.
///
/// Returns the party that produced the response, and the epochs it reports as destroyed.
pub(crate) fn check_destroy_context_response(
    internal_client: &Client,
    response: &DestroyMpcContextResponse,
    context_id: &ContextId,
    extra_data: &[u8],
    domain: &Eip712Domain,
) -> anyhow::Result<(u32, Vec<EpochId>)> {
    let received: DestroyMpcContextPayload = response
        .payload
        .clone()
        .ok_or_else(|| anyhow::anyhow!("the context destruction response carries no payload"))?
        .try_into()?;
    anyhow::ensure!(
        received.destroyed_context_id == *context_id,
        "the context destruction response confirms context {}, but {context_id} was requested",
        received.destroyed_context_id
    );
    anyhow::ensure!(
        received.extra_data == extra_data,
        "the context destruction response carries other extra data than was requested"
    );
    let (party_id, _address) = internal_client.verify_result_signatures(
        &response.signatures,
        // A context destruction response has no deprecated `external_signature`.
        &[],
        &ContextDestructionVerification::new(
            context_id,
            &received.destroyed_epoch_ids,
            extra_data.to_vec(),
        ),
        domain,
        &DSEP_DESTROY_CONTEXT,
        &received,
    )?;
    tracing::info!(
        "Destruction of context {context_id} verified as done by party {party_id}, together with \
         epochs {:?}",
        received.destroyed_epoch_ids
    );
    Ok((party_id, received.destroyed_epoch_ids))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dummy_domain;
    use kms_grpc::rpc_types::ecdsa_signatures;
    use kms_lib::consts::TEST_PARAM;
    use kms_lib::cryptography::signatures::{
        PrivateSigKey, PublicSigKey, compute_eip712_signature, gen_sig_keys,
    };
    use rand::SeedableRng;
    use threshold_types::rng::AesRng;

    /// A client that knows `pk` as party 1 and requests ECDSA only.
    fn client_knowing(pk: PublicSigKey) -> Client {
        let address = pk.address();
        Client::new(
            HashMap::from([(1, pk)]),
            HashMap::new(),
            address,
            None,
            TEST_PARAM,
            None,
        )
    }

    /// A response confirming `confirmed` with `confirmed_epochs`, ECDSA-signed by `sk` over
    /// `signed` with `signed_epochs`.
    fn response(
        sk: &PrivateSigKey,
        (confirmed, confirmed_epochs): (&ContextId, &[EpochId]),
        (signed, signed_epochs): (&ContextId, &[EpochId]),
        extra_data: &[u8],
    ) -> DestroyMpcContextResponse {
        let signature = compute_eip712_signature(
            sk,
            &ContextDestructionVerification::new(signed, signed_epochs, extra_data.to_vec()),
            &dummy_domain(),
        )
        .unwrap();
        let payload = DestroyMpcContextPayload {
            destroyed_context_id: *confirmed,
            destroyed_epoch_ids: confirmed_epochs.to_vec(),
            extra_data: extra_data.to_vec(),
        };
        DestroyMpcContextResponse {
            payload: Some((&payload).into()),
            signatures: ecdsa_signatures(signature),
        }
    }

    #[test]
    fn destroy_context_response_signatures() {
        let mut rng = AesRng::seed_from_u64(0xC0DE);
        let (pk, sk) = gen_sig_keys(&mut rng);
        let client = client_knowing(pk);
        let context_id = ContextId::from_bytes([1u8; 32]);
        let other_context_id = ContextId::from_bytes([2u8; 32]);
        let epochs = [EpochId::from_bytes([3u8; 32]), EpochId::from_bytes([4u8; 32])];
        let extra_data = vec![7u8; 3];
        let domain = dummy_domain();
        let check = |client: &Client, response: &DestroyMpcContextResponse, extra_data: &[u8]| {
            check_destroy_context_response(client, response, &context_id, extra_data, &domain)
        };

        let valid = response(
            &sk,
            (&context_id, &epochs),
            (&context_id, &epochs),
            &extra_data,
        );
        assert_eq!(
            check(&client, &valid, &extra_data).unwrap(),
            (1, epochs.to_vec())
        );

        // A context without epochs, or whose epochs an earlier attempt removed, lists none.
        let no_epochs = response(&sk, (&context_id, &[]), (&context_id, &[]), &extra_data);
        assert_eq!(
            check(&client, &no_epochs, &extra_data).unwrap(),
            (1, Vec::new())
        );

        // A correctly signed confirmation of another context is not a confirmation of ours.
        let other = response(
            &sk,
            (&other_context_id, &epochs),
            (&other_context_id, &epochs),
            &extra_data,
        );
        assert!(check(&client, &other, &extra_data).is_err());

        // The epoch list in the payload must be the one the signature covers.
        let altered_epochs = response(
            &sk,
            (&context_id, &epochs[..1]),
            (&context_id, &epochs),
            &extra_data,
        );
        assert!(check(&client, &altered_epochs, &extra_data).is_err());

        // The extra data is bound into the signature too.
        assert!(check(&client, &valid, &[]).is_err());

        // A client that does not know the signer rejects the response.
        let stranger = client_knowing(gen_sig_keys(&mut rng).0);
        assert!(check(&stranger, &valid, &extra_data).is_err());
    }
}
