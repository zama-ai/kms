use std::collections::{BTreeMap, HashMap};
use std::str::FromStr;

use aes_prng::AesRng;
use hashing::hash_element;
use kms_grpc::{
    ContextId, RequestId,
    kms::v1::{
        CustodianContext, CustodianRecoveryInitRequest, CustodianRecoveryOutput,
        CustodianRecoveryRequest, DestroyCustodianContextRequest, Empty,
        NewCustodianContextRequest,
    },
    kms_service::v1::core_service_endpoint_client::CoreServiceEndpointClient,
};
use kms_lib::backup::{
    DSEP_ATTESTED_BACKUP_PK,
    custodian::{InternalCustodianRecoveryOutput, InternalCustodianSetupMessage},
    operator::InternalRecoveryRequest,
};
use kms_lib::cryptography::signatures::{SigningSchemeType, VerfKeySet};
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
        let Some(attested_digest) = attestation_doc.public_key else {
            anyhow::bail!("Bad response: public key not present in attestation document")
        };
        check_attested_backup_pk(pk.public_key.as_slice(), attested_digest.as_slice())?;

        backup_pks.push(hex::encode(pk.public_key.as_slice()));
    }

    Ok(backup_pks)
}

/// Check that `attested_digest` binds the attestation document to `public_key`.
///
/// The document carries a digest of the key, not the key: the composite backup key does not fit in
/// the attestation document's `public_key` field. The operator computes the same digest in
/// `get_operator_public_key`, so the two sides must agree on
/// [`DSEP_ATTESTED_BACKUP_PK`] and on the digest function.
///
/// Returns an error when the digests differ.
fn check_attested_backup_pk(public_key: &[u8], attested_digest: &[u8]) -> anyhow::Result<()> {
    let expected_digest = hash_element(&DSEP_ATTESTED_BACKUP_PK, public_key);
    if expected_digest.as_slice() != attested_digest {
        anyhow::bail!(
            "Bad response: public key digest {} does not match the attestation document digest {}",
            hex::encode(&expected_digest),
            hex::encode(attested_digest),
        )
    }
    Ok(())
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

pub(crate) async fn do_destroy_custodian_context(
    core_endpoints: &HashMap<CoreConf, CoreServiceEndpointClient<Channel>>,
    custodian_context_id: &RequestId,
) -> anyhow::Result<()> {
    let mut req_tasks = JoinSet::new();
    for ce in core_endpoints.values() {
        let mut cur_client = ce.clone();
        let context_cloned = (*custodian_context_id).into();
        req_tasks.spawn(async move {
            cur_client
                .destroy_custodian_context(tonic::Request::new(DestroyCustodianContextRequest {
                    context_id: Some(context_cloned),
                }))
                .await
        });
    }
    while let Some(inner) = req_tasks.join_next().await {
        let _ = inner??;
    }

    Ok(())
}

pub(crate) async fn do_custodian_recovery_init(
    core_endpoints: &HashMap<CoreConf, CoreServiceEndpointClient<Channel>>,
    overwrite_ephemeral_key: bool,
    custodian_context_id: Option<kms_grpc::kms::v1::RequestId>,
) -> anyhow::Result<Vec<InternalRecoveryRequest>> {
    let mut req_tasks = JoinSet::new();
    for (core_conf, ce) in core_endpoints.iter() {
        let mut cur_client = ce.clone();
        let core_conf = core_conf.clone();
        let custodian_context_id = custodian_context_id.clone();
        req_tasks.spawn(async move {
            (
                core_conf,
                cur_client
                    .custodian_recovery_init(tonic::Request::new(CustodianRecoveryInitRequest {
                        overwrite_ephemeral_key,
                        custodian_context_id,
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
        .map(CustodianRecoveryOutput::try_from)
        .collect::<anyhow::Result<Vec<_>>>()?;

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

/// Parse the `SCHEME=VALUE` arguments naming the operator verification keys a recovery request
/// must carry. Each scheme may be named once.
pub(crate) fn parse_expected_operator_keys(
    raw: &[String],
) -> anyhow::Result<BTreeMap<SigningSchemeType, String>> {
    let mut expected = BTreeMap::new();
    for arg in raw {
        let (scheme, value) = arg
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("expected SCHEME=VALUE, got {arg:?}"))?;
        let scheme = SigningSchemeType::from_str(scheme.trim())
            .map_err(|_| anyhow::anyhow!("unknown signing scheme in {arg:?}"))?;
        if expected
            .insert(scheme, normalized_key_text(value))
            .is_some()
        {
            anyhow::bail!("the expected {scheme} operator key is given more than once");
        }
    }
    Ok(expected)
}

/// The comparable form of a key's `0x` text: lowercase, and `0x` prefixed. An Ethereum address
/// prints with a mixed-case checksum, which the comparison ignores.
fn normalized_key_text(value: &str) -> String {
    let value = value.trim().to_ascii_lowercase();
    if value.starts_with("0x") {
        value
    } else {
        format!("0x{value}")
    }
}

/// Check the operator's verification keys against `expected`, failing on any mismatch, then
/// print every key so that those not given can be checked by hand.
///
/// The core may have taken `keys` from its recovery material rather than from a trusted source,
/// so whatever is checked here, or by hand, is the security the recovery has. The per-scheme
/// digests are the ones `kms-custodian` prints, so operator and custodians compare the same
/// values.
pub(crate) fn report_operator_keys(
    keys: &VerfKeySet,
    expected: &BTreeMap<SigningSchemeType, String>,
) -> anyhow::Result<()> {
    for (scheme, value) in expected {
        let key = keys.get(*scheme).ok_or_else(|| {
            anyhow::anyhow!("an operator {scheme} key is expected, but the request carries none")
        })?;
        let actual = normalized_key_text(&key.address_text());
        if actual != *value {
            anyhow::bail!("the operator {scheme} key is {actual}, but {value} is expected");
        }
    }
    for scheme in keys.schemes() {
        let key = keys.require(scheme)?;
        let text = key.address_text();
        let digest = hex::encode(key.digest());
        if expected.contains_key(&scheme) {
            tracing::info!("Operator {scheme} key {text} (digest {digest}) is the expected one");
        } else {
            tracing::warn!(
                "MANUALLY VALIDATE THE OPERATOR VERIFICATION KEY BEFORE PASSING THE RECOVERY \
                 REQUEST TO THE CUSTODIANS! Operator {scheme} key {text} (digest {digest})"
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{DSEP_ATTESTED_BACKUP_PK, check_attested_backup_pk};
    use super::{normalized_key_text, parse_expected_operator_keys, report_operator_keys};
    use aes_prng::AesRng;
    use hashing::hash_element;
    use kms_lib::backup::BACKUP_SIGNING_SCHEMES;
    use kms_lib::cryptography::signatures::{SigningSchemeType, test_support::seeded_verf_key_set};
    use rand::SeedableRng;
    use std::collections::BTreeMap;

    /// A key whose digest is pinned by [`REFERENCE_DIGEST`].
    fn reference_public_key() -> Vec<u8> {
        (0u8..64).collect()
    }

    /// SHAKE-256 over `DSEP_ATTESTED_BACKUP_PK || reference_public_key()`, 32 bytes of output.
    ///
    /// The value is pinned rather than recomputed. A change to the domain separator or to the
    /// digest function breaks every operator that runs an older binary, so it must fail here first.
    const REFERENCE_DIGEST: &str =
        "44a2cf7b4681e02de6f23e04a35513fecff192c0c9b7678a692d2ee48fceb919";

    #[test]
    fn digest_matches_reference() {
        let digest = hash_element(&DSEP_ATTESTED_BACKUP_PK, reference_public_key().as_slice());
        assert_eq!(hex::encode(&digest), REFERENCE_DIGEST);
    }

    #[test]
    fn accepts_reference_digest() {
        let attested_digest = hex::decode(REFERENCE_DIGEST).unwrap();
        check_attested_backup_pk(reference_public_key().as_slice(), &attested_digest).unwrap();
    }

    #[test]
    fn rejects_digest_of_another_key() {
        let other_key: Vec<u8> = (1u8..65).collect();
        let attested_digest = hash_element(&DSEP_ATTESTED_BACKUP_PK, other_key.as_slice());
        let err = check_attested_backup_pk(reference_public_key().as_slice(), &attested_digest)
            .unwrap_err()
            .to_string();
        assert!(err.contains(REFERENCE_DIGEST), "unexpected error: {err}");
    }

    #[test]
    fn rejects_undigested_key() {
        let public_key = reference_public_key();
        let err = check_attested_backup_pk(public_key.as_slice(), public_key.as_slice())
            .unwrap_err()
            .to_string();
        assert!(err.contains(REFERENCE_DIGEST), "unexpected error: {err}");
    }

    #[test]
    fn rejects_digest_under_another_domain_separator() {
        let other_dsep = *b"OTHERDSP";
        let attested_digest = hash_element(&other_dsep, reference_public_key().as_slice());
        assert!(
            check_attested_backup_pk(reference_public_key().as_slice(), &attested_digest).is_err()
        );
    }

    #[test]
    fn expected_keys_parse_once_per_scheme() {
        let parsed = parse_expected_operator_keys(&["mldsa87=AB12".to_string()]).unwrap();
        assert_eq!(parsed[&SigningSchemeType::MlDsa87], "0xab12");

        let twice = ["MlDsa87=0x01".to_string(), "MlDsa87=0x02".to_string()];
        assert!(parse_expected_operator_keys(&twice).is_err());
        assert!(parse_expected_operator_keys(&["MlDsa87".to_string()]).is_err());
        assert!(parse_expected_operator_keys(&["NoSuchScheme=0x01".to_string()]).is_err());
    }

    #[test]
    fn operator_keys_must_match_every_expected_key() {
        let keys = seeded_verf_key_set(&mut AesRng::seed_from_u64(0), BACKUP_SIGNING_SCHEMES);
        let other = seeded_verf_key_set(&mut AesRng::seed_from_u64(1), BACKUP_SIGNING_SCHEMES);
        let text = |set: &kms_lib::cryptography::signatures::VerfKeySet, scheme| {
            set.require(scheme).unwrap().address_text()
        };

        // Nothing expected: everything is left to the operator.
        report_operator_keys(&keys, &BTreeMap::new()).unwrap();

        // The checksummed address and the digest match whatever their case.
        let expected = BTreeMap::from([
            (
                SigningSchemeType::Ecdsa256k1,
                normalized_key_text(&text(&keys, SigningSchemeType::Ecdsa256k1).to_uppercase()),
            ),
            (
                SigningSchemeType::MlDsa87,
                normalized_key_text(&text(&keys, SigningSchemeType::MlDsa87)),
            ),
        ]);
        report_operator_keys(&keys, &expected).unwrap();

        // One wrong key is enough to fail.
        let wrong = BTreeMap::from([(
            SigningSchemeType::MlDsa87,
            normalized_key_text(&text(&other, SigningSchemeType::MlDsa87)),
        )]);
        assert!(report_operator_keys(&keys, &wrong).is_err());

        // So is expecting a key the request does not carry.
        let absent = BTreeMap::from([(SigningSchemeType::Ed25519, "0x01".to_string())]);
        assert!(report_operator_keys(&keys, &absent).is_err());
    }
}
