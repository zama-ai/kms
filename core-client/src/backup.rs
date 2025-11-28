use std::collections::HashMap;

use aes_prng::AesRng;
use kms_grpc::{
    kms::v1::{
        CustodianContext, CustodianRecoveryInitRequest, CustodianRecoveryOutput,
        CustodianRecoveryRequest, Empty, NewCustodianContextRequest, OperatorBackupOutput,
    },
    kms_service::v1::core_service_endpoint_client::CoreServiceEndpointClient,
    RequestId,
};
use kms_lib::backup::{
    custodian::{InternalCustodianRecoveryOutput, InternalCustodianSetupMessage},
    operator::InternalRecoveryRequest,
};
use threshold_fhe::{
    execution::runtime::party::Role,
    hashing::{hash_element, DomainSep},
};
use tokio::task::JoinSet;
use tonic::transport::Channel;

pub(crate) async fn do_get_operator_pub_keys(
    core_endpoints: &HashMap<u32, CoreServiceEndpointClient<Channel>>,
) -> anyhow::Result<Vec<String>> {
    let mut req_tasks = JoinSet::new();
    for (_party_id, ce) in core_endpoints.iter() {
        let mut cur_client = ce.clone();
        req_tasks.spawn(async move {
            cur_client
                .get_operator_public_key(tonic::Request::new(kms_grpc::kms::v1::Empty {}))
                .await
        });
    }

    let mut backup_pks = Vec::with_capacity(core_endpoints.len());

    while let Some(inner) = req_tasks.join_next().await {
        let pk = inner??.into_inner();
        let attestation_doc = attestation_doc_validation::validate_and_parse_attestation_doc(
            &pk.attestation_document,
        )?;
        let Some(attested_pk) = attestation_doc.public_key else {
            anyhow::bail!("Bad response: public key not present in attestation document")
        };

        if pk.public_key.as_slice() != attested_pk.as_slice() {
            let dsep: DomainSep = *b"EQUALITY";
            let pk_hash = hex::encode(hash_element(&dsep, pk.public_key.as_slice()));
            let att_pk_hash = hex::encode(hash_element(&dsep, attested_pk.as_slice()));
            anyhow::bail!("Bad response: public key with hash {} does not match attestation document public key with hash {}", pk_hash, att_pk_hash)
        };

        backup_pks.push(hex::encode(pk.public_key.as_slice()));
    }

    Ok(backup_pks)
}

pub(crate) async fn do_new_custodian_context(
    core_endpoints: &HashMap<u32, CoreServiceEndpointClient<Channel>>,
    rng: &mut AesRng,
    threshold: u32,
    custodian_setup_msg: Vec<InternalCustodianSetupMessage>,
) -> anyhow::Result<RequestId> {
    let context_id = RequestId::new_random(rng);
    let mut req_tasks = JoinSet::new();
    let mut custodian_nodes = Vec::new();
    for cur_setup in custodian_setup_msg {
        custodian_nodes.push(cur_setup.try_into()?);
    }
    let new_context = CustodianContext {
        custodian_nodes,
        context_id: Some(context_id.into()),
        threshold,
    };
    for (_party_id, ce) in core_endpoints.iter() {
        let mut cur_client = ce.clone();
        let new_context_cloned = new_context.clone();
        req_tasks.spawn(async move {
            cur_client
                .new_custodian_context(tonic::Request::new(NewCustodianContextRequest {
                    new_context: Some(new_context_cloned),
                }))
                .await
        });
    }
    while let Some(inner) = req_tasks.join_next().await {
        let _ = inner??;
    }

    Ok(context_id)
}

pub(crate) async fn do_custodian_recovery_init(
    core_endpoints: &HashMap<u32, CoreServiceEndpointClient<Channel>>,
    overwrite_ephemeral_key: bool,
) -> anyhow::Result<Vec<InternalRecoveryRequest>> {
    let mut req_tasks = JoinSet::new();
    for (_party_id, ce) in core_endpoints.iter() {
        let mut cur_client = ce.clone();
        req_tasks.spawn(async move {
            cur_client
                .custodian_recovery_init(tonic::Request::new(CustodianRecoveryInitRequest {
                    overwrite_ephemeral_key,
                }))
                .await
        });
    }

    let mut res = Vec::new();
    while let Some(inner) = req_tasks.join_next().await {
        let cur_rec_req = inner??;
        let cur_inner_rec = cur_rec_req.into_inner();
        res.push(cur_inner_rec.try_into()?);
    }

    Ok(res)
}

pub(crate) async fn do_custodian_backup_recovery(
    core_endpoints: &HashMap<u32, CoreServiceEndpointClient<Channel>>,
    custodian_context_id: RequestId,
    custodian_recovery_outputs: Vec<InternalCustodianRecoveryOutput>,
) -> anyhow::Result<()> {
    let mut req_tasks = JoinSet::new();
    for (core_idx, ce) in core_endpoints.iter() {
        let mut cur_client = ce.clone();
        let core_idx = *core_idx as usize;
        // We assume the core client endpoints are ordered by the server identity
        let mut cur_recoveries = Vec::new();
        for cur_recover in custodian_recovery_outputs.iter() {
            // Find the recoveries designated for the correct server
            if cur_recover.operator_role == Role::indexed_from_one(core_idx) {
                cur_recoveries.push(CustodianRecoveryOutput {
                    backup_output: Some(OperatorBackupOutput {
                        signcryption: cur_recover.signcryption.payload.clone(),
                        pke_type: cur_recover.signcryption.pke_type as i32,
                        signing_type: cur_recover.signcryption.signing_type as i32,
                    }),
                    custodian_role: cur_recover.custodian_role.one_based() as u64,
                    operator_role: cur_recover.operator_role.one_based() as u64,
                });
            }
        }
        req_tasks.spawn(async move {
            cur_client
                .custodian_backup_recovery(tonic::Request::new(CustodianRecoveryRequest {
                    custodian_context_id: Some(custodian_context_id.into()),
                    custodian_recovery_outputs: cur_recoveries,
                }))
                .await
        });
    }

    while let Some(inner) = req_tasks.join_next().await {
        let _ = inner??;
    }

    Ok(())
}

pub(crate) async fn do_restore_from_backup(
    core_endpoints: &mut HashMap<u32, CoreServiceEndpointClient<Channel>>,
) -> anyhow::Result<()> {
    let mut req_tasks = JoinSet::new();
    for (_party_id, ce) in core_endpoints.iter_mut() {
        let mut cur_client = ce.clone();
        req_tasks.spawn(async move {
            cur_client
                .restore_from_backup(tonic::Request::new(Empty {}))
                .await
        });
    }

    while let Some(inner) = req_tasks.join_next().await {
        let _ = inner??;
    }

    Ok(())
}
