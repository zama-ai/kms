use std::collections::HashMap;

use aes_prng::AesRng;
use hashing::{DomainSep, hash_element};
use kms_grpc::{
    ContextId, RequestId,
    kms::v1::{
        CustodianContext, CustodianRecoveryInitRequest, CustodianRecoveryOutput,
        CustodianRecoveryRequest, Empty, NewCustodianContextRequest, OperatorBackupOutput,
    },
    kms_service::v1::core_service_endpoint_client::CoreServiceEndpointClient,
};
use kms_lib::backup::{
    custodian::{InternalCustodianRecoveryOutput, InternalCustodianSetupMessage},
    operator::InternalRecoveryRequest,
};
use tokio::task::JoinSet;
use tonic::transport::Channel;

use crate::CoreConf;

pub(crate) async fn do_get_operator_pub_keys(
    core_endpoints: &HashMap<CoreConf, CoreServiceEndpointClient<Channel>>,
) -> anyhow::Result<Vec<String>> {
    let mut req_tasks = JoinSet::new();
    for ce in core_endpoints.values() {
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
            anyhow::bail!(
                "Bad response: public key with hash {} does not match attestation document public key with hash {}",
                pk_hash,
                att_pk_hash
            )
        };

        backup_pks.push(hex::encode(pk.public_key.as_slice()));
    }

    Ok(backup_pks)
}

pub(crate) async fn do_new_custodian_context(
    core_endpoints: &HashMap<CoreConf, CoreServiceEndpointClient<Channel>>,
    rng: &mut AesRng,
    threshold: u32,
    custodian_setup_msg: Vec<InternalCustodianSetupMessage>,
    mpc_context_id: ContextId,
) -> anyhow::Result<RequestId> {
    let custodian_context_id = RequestId::new_random(rng);
    let mut req_tasks = JoinSet::new();
    let mut custodian_nodes = Vec::new();
    for cur_setup in custodian_setup_msg {
        custodian_nodes.push(cur_setup.try_into()?);
    }
    let new_context = CustodianContext {
        custodian_nodes,
        custodian_context_id: Some(custodian_context_id.into()),
        threshold,
    };
    for ce in core_endpoints.values() {
        let mut cur_client = ce.clone();
        let new_context_cloned = new_context.clone();
        let mpc_context_id_cloned = mpc_context_id;
        req_tasks.spawn(async move {
            cur_client
                .new_custodian_context(tonic::Request::new(NewCustodianContextRequest {
                    new_custodian_context: Some(new_context_cloned),
                    mpc_context_id: Some(mpc_context_id_cloned.into()),
                }))
                .await
        });
    }
    while let Some(inner) = req_tasks.join_next().await {
        let _ = inner??;
    }

    Ok(custodian_context_id)
}

pub(crate) async fn do_custodian_recovery_init(
    core_endpoints: &HashMap<CoreConf, CoreServiceEndpointClient<Channel>>,
    overwrite_ephemeral_key: bool,
) -> anyhow::Result<Vec<InternalRecoveryRequest>> {
    let mut req_tasks = JoinSet::new();
    for (core_conf, ce) in core_endpoints.iter() {
        let mut cur_client = ce.clone();
        let core_conf = core_conf.clone();
        req_tasks.spawn(async move {
            (
                core_conf,
                cur_client
                    .custodian_recovery_init(tonic::Request::new(CustodianRecoveryInitRequest {
                        overwrite_ephemeral_key,
                    }))
                    .await,
            )
        });
    }

    let mut res = Vec::new();
    while let Some(inner) = req_tasks.join_next().await {
        let (core_conf, cur_rec_req) = inner?;
        let cur_inner_rec = cur_rec_req?.into_inner();
        res.push((core_conf, cur_inner_rec.try_into()?));
    }
    res.sort_by_key(|a| a.0.party_id);

    Ok(res.into_iter().map(|(_, v)| v).collect())
}

/// Send every custodian recovery output to every operator.
///
/// We no longer carry an `operator_verification_key` hint on the wire or in the on-disk
/// `InternalCustodianRecoveryOutput`. Each operator's `filter_custodian_data` will skip outputs not
/// addressed to it: they fail `validate_signcryption` because the signcryption's `receiver_id` was
/// bound to a specific operator at backup time. Bandwidth is `N × M` outputs (operators × custodians),
/// which is sub-megabyte even at the upper end of typical KMS sizes.
pub(crate) async fn do_custodian_backup_recovery(
    core_endpoints: &HashMap<CoreConf, CoreServiceEndpointClient<Channel>>,
    custodian_context_id: RequestId,
    custodian_recovery_outputs: Vec<InternalCustodianRecoveryOutput>,
) -> anyhow::Result<()> {
    if custodian_recovery_outputs.is_empty() {
        anyhow::bail!("At least one custodian recovery output is required");
    }
    let proto_outputs: Vec<CustodianRecoveryOutput> = custodian_recovery_outputs
        .into_iter()
        .map(|out| CustodianRecoveryOutput {
            backup_output: Some(OperatorBackupOutput {
                signcryption: out.signcryption.payload,
                pke_type: out.signcryption.pke_type as i32,
                signing_type: out.signcryption.signing_type as i32,
            }),
            custodian_role: out.custodian_role.one_based() as u64,
        })
        .collect();

    let mut req_tasks = JoinSet::new();
    for ce in core_endpoints.values() {
        let mut cur_client = ce.clone();
        let outputs = proto_outputs.clone();
        req_tasks.spawn(async move {
            cur_client
                .custodian_backup_recovery(tonic::Request::new(CustodianRecoveryRequest {
                    custodian_context_id: Some(custodian_context_id.into()),
                    custodian_recovery_outputs: outputs,
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
    core_endpoints: &mut HashMap<CoreConf, CoreServiceEndpointClient<Channel>>,
) -> anyhow::Result<()> {
    let mut req_tasks = JoinSet::new();
    for ce in core_endpoints.values_mut() {
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
