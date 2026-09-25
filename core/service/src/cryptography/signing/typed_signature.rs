//! A signature together with the scheme that produced it.

use super::SigningSchemeType;
use kms_grpc::kms::v1::TypedSignature;
use serde::{Deserialize, Serialize};
use tfhe_versionable::{Versionize, VersionsDispatch};

#[derive(Clone, Serialize, Deserialize, VersionsDispatch)]
pub enum StoredTypedSignatureVersions {
    V0(StoredTypedSignature),
}

/// A single KMS signature together with the scheme that produced it, in the
/// form persisted inside result metadata.
///
/// This is the stored twin of the gRPC [`TypedSignature`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Versionize)]
#[versionize(StoredTypedSignatureVersions)]
pub struct StoredTypedSignature {
    pub scheme: SigningSchemeType,
    pub signature: Vec<u8>,
}

impl StoredTypedSignature {
    /// The `signatures` list of a result that carries nothing but its
    /// ECDSA/EIP-712 signature.
    pub fn ecdsa_only(external_signature: Vec<u8>) -> Vec<Self> {
        vec![StoredTypedSignature {
            scheme: SigningSchemeType::Ecdsa256k1,
            signature: external_signature,
        }]
    }
}

impl From<&StoredTypedSignature> for TypedSignature {
    fn from(value: &StoredTypedSignature) -> Self {
        TypedSignature {
            scheme: value.scheme.as_wire(),
            signature: value.signature.clone(),
        }
    }
}
