// TODO: verify once HTTPZ SC is finished
use alloy_primitives::Bytes;
use alloy_sol_types::sol;

sol! {
    /// Protocol metadata struct
    struct ProtocolMetadata {
        string name;
        string website;
    }

    /// KMS node struct
    struct KmsNode {
        bytes identity;
        address gateway;
        string ipAddress;
    }

    /// Coprocessor struct
    struct Coprocessor {
        bytes identity;
    }

    /// Network struct
    struct Network {
        uint256 chainId;
        string name;
        string rpcUrl;
    }

    /// Event emitted when a new FHE key is generated
    event FheKeyGenerated(
        uint256 indexed keyId,
        bytes publicKey,
        bytes[] signatures
    );

    /// Event emitted when a new CRS is generated
    event CrsGenerated(
        uint256 indexed crsId,
        bytes crs,
        bytes[] signatures
    );

    /// Event emitted when FHE parameters are updated
    event FheParametersUpdated(
        uint256 indexed parameterId,
        bytes parameters
    );
}

/// Represents FHE key generation data
#[derive(Debug, Clone)]
pub struct FheKeyGenerationData {
    pub key_id: u64,
    pub public_key: Bytes,
    pub signatures: Vec<Bytes>,
}

/// Represents CRS generation data
#[derive(Debug, Clone)]
pub struct CrsGenerationData {
    pub crs_id: u64,
    pub crs: Bytes,
    pub signatures: Vec<Bytes>,
}

impl From<FheKeyGenerated> for FheKeyGenerationData {
    fn from(event: FheKeyGenerated) -> Self {
        Self {
            key_id: event.keyId.try_into().unwrap(),
            public_key: event.publicKey,
            signatures: event.signatures,
        }
    }
}

impl From<CrsGenerated> for CrsGenerationData {
    fn from(event: CrsGenerated) -> Self {
        Self {
            crs_id: event.crsId.try_into().unwrap(),
            crs: event.crs,
            signatures: event.signatures,
        }
    }
}
