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
        }

        struct Coprocessor {
            address connectorAddress;
            bytes identity;
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

        event Initialization(ProtocolMetadata protocolMetadata, address[] admins);
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
    }
}

pub use IHTTPZ::*;
