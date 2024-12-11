/// Messages for interacting with external contracts (CSC, IPSC, etc.)
///
/// Note that we need to do this instead of importing the msg directly from the CSC's
/// crate because having a contract as a dependency of another one creates some conflict when
/// building them
///
/// This means:
/// - the enum must contain the targeted methods's name as a variant
/// - each variant must provide the necessary inputs as specified in the method's definition
use serde::Serialize;
use strum_macros::EnumString;

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
