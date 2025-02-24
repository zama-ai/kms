// TODO: verify once HTTPZ SC is finished
use alloy_sol_types::sol;

sol! {
    #[sol(rpc)]
    #[derive(Debug)]
    interface IHTTPZ {
        struct ProtocolMetadata {
            string name;
            string website;
        }

        struct KmsNode {
            address connectorAddress;
            bytes identity;
            string ipAddress;
            bytes[] signedNodes;
            address daAddress;
        }

        struct Coprocessor {
            address connectorAddress;
            bytes identity;
            address daAddress;
        }

        struct Network {
            uint256 chainId;
            address httpzLibrary;
            address acl;
            string name;
            string website;
        }

        struct FheParams {
            string dummy;
        }

        error PreprocessKeygenAlreadyOngoing();
        error PreprocessKeygenNotOngoing();
        error PreprocessKeyIdNull();
        error PreprocessKeygenKmsNodeAlreadyResponded(uint256 preKeyId);
        error PreprocessKskgenAlreadyOngoing();
        error PreprocessKskgenNotOngoing();
        error PreprocessKskIdNull();
        error PreprocessKskgenKmsNodeAlreadyResponded(uint256 preKskId);
        error KeygenAlreadyOngoing();
        error KeygenNotOngoing();
        error KeyIdNull();
        error KeygenKmsNodeAlreadyResponded(uint256 keyId);
        error KeygenRequiresPreprocessing();
        error CrsgenAlreadyOngoing();
        error CrsgenNotOngoing();
        error CrsIdNull();
        error CrsgenKmsNodeAlreadyResponded(uint256 crsId);
        error CrsgenRequiresPreprocessing();
        error KskgenAlreadyOngoing();
        error KskgenNotOngoing();
        error KskIdNull();
        error KskgenKmsNodeAlreadyResponded(uint256 kskId);
        error KskgenRequiresPreprocessing();
        error ActivateKeyAlreadyOngoing();
        error ActivateKeyNotOngoing();
        error ActivateKeyCoprocessorAlreadyResponded(uint256 keyId);
        error ActivateKeyRequiresKskgen();
        error KmsThresholdTooHigh(uint256 threshold, uint256 nParties);

        event Initialization(
            ProtocolMetadata metadata,
            address[] admins,
            uint256 kmsThreshold,
            KmsNode[] kmsNodes,
            Coprocessor[] coprocessors
        );
        event KmsNodesInit(bytes[] identities);
        event KmsServiceReady(bytes[] identities);
        event CoprocessorsInit(bytes[] identities);
        event CoprocessorServiceReady(bytes[] identities);
        event AddNetwork(uint256 chainId);
        event PreprocessKeygenRequest(FheParams fheParams);
        event PreprocessKeygenResponse(uint256 preKeyId);
        event PreprocessKskgenRequest(FheParams fheParams);
        event PreprocessKskgenResponse(uint256 preKskId);
        event KeygenRequest(uint256 preKeyId, FheParams fheParams);
        event KeygenResponse(uint256 keygenId);
        event CrsgenRequest(uint256 preCrsId, FheParams fheParams);
        event CrsgenResponse(uint256 crsId);
        event KskgenRequest(uint256 preKskId, uint256 sourceKeyId, uint256 destKeyId, FheParams fheParams);
        event KskgenResponse(uint256 kskId);
        event ActivateKeyRequest(uint256 keyId);
        event ActivateKeyResponse(uint256 keyId);
        event UpdateFheParams(FheParams newFheParams);
        event UpdateKmsThreshold(uint256 newKmsThreshold);

        function initialize(
            ProtocolMetadata calldata initialMetadata,
            address[] calldata initialAdmins,
            uint256 initialKmsThreshold,
            KmsNode[] calldata initialKmsNodes,
            Coprocessor[] calldata initialCoprocessors
        ) external;

        function addNetwork(Network calldata network) external;
        function updateKmsThreshold(uint256 newKmsThreshold) external;
        function isAdmin(address adminAddress) external view returns (bool);
        function isKmsNode(address kmsNodeAddress) external view returns (bool);
        function isCoprocessor(address coprocessorAddress) external view returns (bool);
        function isNetwork(uint256 chainId) external view returns (bool);
        function getKmsMajorityThreshold() external view returns (uint256);
        function getKmsReconstructionThreshold() external view returns (uint256);
        function getCoprocessorMajorityThreshold() external view returns (uint256);
    }
}

pub use IHTTPZ::*;
