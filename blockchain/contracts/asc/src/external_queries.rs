/// Messages for interacting with external contracts (CSC, IPSC, etc.)
///
/// Note that we need to do this instead of importing the msg directly from the CSC's
/// crate because having a contract as a dependency of another one creates some conflict when
/// building them
///
/// This means:
/// - the enum must contain the targeted methods's name as a variant
/// - each variant must provide the necessary inputs as specified in the method's definition
use cosmwasm_schema::cw_serde;
use events::kms::{
    CrsGenResponseValues, CrsGenValues, DecryptResponseValues, DecryptValues, InsecureCrsGenValues,
    InsecureKeyGenValues, KeyGenResponseValues, KeyGenValues, KmsEvent, ReencryptResponseValues,
    ReencryptValues, TransactionId, VerifyProvenCtResponseValues, VerifyProvenCtValues,
};
use serde::Serialize;
use strum_macros::EnumString;

/// Message inputs for verifying a proof using an IPSC
#[cw_serde]
pub struct ProofPayload {
    pub proof: String,
    pub ciphertext_handles: String,
}

/// Message for verifying a proof using an IPSC
#[cw_serde]
pub struct ProofMessage {
    pub verify_proof: ProofPayload,
}

/// Query messages for getting configuration parameters from the CSC
///
/// Important: serde's rename must exactly match the CSC's associated method name
#[derive(EnumString, Serialize)]
pub enum KmsConfigQuery {
    #[serde(rename = "get_response_count_for_majority_vote")]
    GetResponseCountForMajorityVote {},
    #[serde(rename = "get_response_count_for_reconstruction")]
    GetResponseCountForReconstruction {},
}

/// Query messages for interacting with the BSC
///
/// Important: serde's rename must exactly match the BSC's associated method name
#[derive(EnumString, Serialize)]
pub enum BscQueryMsg {
    #[serde(rename = "get_key_gen_response_values")]
    KeyGenResponseValues { key_id: String },

    #[serde(rename = "get_crs_gen_response_values")]
    CrsGenResponseValues { crs_id: String },

    #[serde(rename = "get_transaction")]
    Transaction { txn_id: TransactionId },

    #[serde(rename = "get_operations_values_from_event")]
    OperationsValuesFromEvent { event: KmsEvent },
}

/// Execution messages for interacting with the BSC
///
/// Important: serde's rename must exactly match the BSC's associated method name
#[derive(EnumString, Serialize)]
pub enum BscExecMsg {
    #[serde(rename = "key_gen_preproc_request")]
    KeyGenPreprocRequest {},

    #[serde(rename = "key_gen_preproc_response")]
    KeyGenPreprocResponse { txn_id: TransactionId },

    #[serde(rename = "key_gen_request")]
    KeyGenRequest { keygen: KeyGenValues },

    #[serde(rename = "key_gen_response")]
    KeyGenResponse {
        txn_id: TransactionId,
        keygen_response: KeyGenResponseValues,
    },

    #[serde(rename = "insecure_key_gen_request")]
    InsecureKeyGenRequest {
        insecure_key_gen: InsecureKeyGenValues,
    },

    #[serde(rename = "insecure_key_gen_response")]
    InsecureKeyGenResponse {
        txn_id: TransactionId,
        keygen_response: KeyGenResponseValues,
    },

    #[serde(rename = "crs_gen_request")]
    CrsGenRequest { crs_gen: CrsGenValues },

    #[serde(rename = "crs_gen_response")]
    CrsGenResponse {
        txn_id: TransactionId,
        crs_gen_response: CrsGenResponseValues,
    },

    #[serde(rename = "insecure_crs_gen_request")]
    InsecureCrsGenRequest {
        insecure_crs_gen: InsecureCrsGenValues,
    },

    #[serde(rename = "insecure_crs_gen_response")]
    InsecureCrsGenResponse {
        txn_id: TransactionId,
        crs_gen_response: CrsGenResponseValues,
    },

    #[serde(rename = "decryption_request")]
    DecryptionRequest { decrypt: DecryptValues },

    #[serde(rename = "decryption_response")]
    DecryptionResponse {
        txn_id: TransactionId,
        decrypt_response: DecryptResponseValues,
    },

    #[serde(rename = "reencryption_request")]
    ReencryptionRequest { reencrypt: ReencryptValues },

    #[serde(rename = "reencryption_response")]
    ReencryptionResponse {
        txn_id: TransactionId,
        reencrypt_response: ReencryptResponseValues,
    },

    #[serde(rename = "verify_proven_ct_request")]
    VerifyProvenCtRequest {
        verify_proven_ct: VerifyProvenCtValues,
    },

    #[serde(rename = "verify_proven_ct_response")]
    VerifyProvenCtResponse {
        txn_id: TransactionId,
        verify_proven_ct_response: VerifyProvenCtResponseValues,
    },
}
