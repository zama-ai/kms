# KMS Core gRPC service specifications

Interactions with KMS core happens through a gRPC service.
In the following we document all the exposed endpoints, detailing for each endpoint the expected input and the expected output of the RPC.

## gRPC data types

<details>
    <summary>RequestId</summary>

### Definition

```proto
message RequestId { string request_id = 1;}
```

### Description

This is used as a unique identifier to each request.

`request_id` must be a 32 bytes hex string, without a `0x` prefix

If a request contains a malformed `request_id`, the response will be an error with `tonic::Code::InvalidArgument`.

</details>

<details>
    <summary>FheType</summary>

### Definition

```proto
enum FheType {
  Ebool = 0;
  Euint4 = 1;
  Euint8 = 2;
  Euint16 = 3;
  Euint32 = 4;
  Euint64 = 5;
  Euint128 = 6;
  Euint160 = 7;
  Euint256 = 8;
  Euint512 = 9;
  Euint1024 = 10;
  Euint2048 = 11;
}
```

### Description

This enum is used as metadata that accompanies a ciphertext to specify its underlying type.
</details>

<details>
    <summary>FheParameter</summary>

### Definition

```proto
enum FheParameter {
  default = 0;
  test = 1;
}
```

### Description

This enum is used to specify the TFHE parameters to use.

__NOTE__: The `test` variant refers to __insecure__ parameters and should __never__ be used in production.

</details>

<details>
    <summary>Eip712DomainMsg</summary>

### Definition

```proto
message Eip712DomainMsg {
  string name = 1;
  string version = 2;
  bytes chain_id = 3; // Encoded as a 32 byte big-endian number
  string verifying_contract = 4;
  optional bytes salt = 5;
}
```

### Description

This is the domain as defined in the [Eip712 standard](https://eips.ethereum.org/EIPS/eip-712#definition-of-domainseparator), which is then hashed into the domain separator.

</details>

<details>
    <summary>SignedPubDataHandle</summary>

### Definition

```proto
message SignedPubDataHandle {
  string key_handle = 1;
  bytes signature = 2;
  bytes external_signature = 3;
}
```

### Description

This is the common structure for all public cryptographic material (i.e public TFHE keys and the CRS).

- `key_handle`: a 256 bits `SHAKE-256` hash of the `tfhe::safe_serialization` of the underlying struct. This handle serves as the `URI` to locate the actual object in the `storage`.
- `signature`: a `bincode::serialize` of `Secp256k1` signature on the `key_handle`. With the `s` value normalized.
- `external_signature`: a `EIP-712` signature on the _solidity-compatible_  256 bits `SHAKE-256` hash of the `tfhe::safe_serialization` of the underlying struct. Observe the same signing key is used as for the above `signature`.

__NOTE__: `signature` and `external_signature` look quite redundant.
</details>

<details>
    <summary>KeySetConfig</summary>

### Definition

```proto
message KeySetConfig {
  KeySetType keyset_type = 1;
  StandardKeySetConfig standard_keyset_config = 2;
}

```

### Description

This is the configuration describing which key components and settings, with which they should be generated, for key generation.

- `KeySetType` The type of keyset.
- `StandardKeySetConfig` The configuration and information about generation of key switching keys. It must be set if `KeySetType::Standard` is set.

</details>

<details>
    <summary>KeySetType</summary>

### Definition

```proto
enum KeySetType {
  Standard = 0;
  DecompressionOnly = 1;
}
```

### Description

This is the enum describing the choice of key switching associated with a key.

- `Standard` The standard keyset usually consists of the computation key, public key and compression/decompression keys.
- `DecompressionOnly` Only a decompression key is generated using this variant, which is used for supporting key rotation.

</details>

<details>
    <summary>StandardKeySetConfig</summary>

### Definition

```proto
enum StandardKeySetConfig {
  ComputeKeyType compute_key_type = 1;
  KeySetCompressionConfig keyset_compression_config = 2;
}
```

### Description

This is the configuration used for making key switching keys.

- `compute_key_type`: An enum expressing what kind of computation key in use. Currently `CPU` is the only option.
- `keyset_compression_config`: An enum expressing settings for compression key generation. Can be either `Generate` or `UseExisting`.

</details>

<details>
    <summary>KeySetAddedInfo</summary>

### Definition

```proto
message KeySetAddedInfo {
  RequestId compression_keyset_id = 1;
  RequestId from_keyset_id_decompression_only = 2;
  RequestId to_keyset_id_decompression_only = 3;
}
```

### Description

This is additional configuration info used for making key switching keys.

- `compression_keyset_id`: The `RequestId` of an existing keyset for which we will reuse the existing secret key. This _must_ be set if `KeySetCompressionConfig::UseExisting` is used.
- `from_keyset_id_decompression_only`: The `RequestId` of the key set to convert _from_ when computing a key switching key. Must be set if `KeySetType::DecompressionOnly` is used
- `to_keyset_id_decompression_only`: The `RequestId` of the key set to convert _to_ when computing a key switching key. Must be set if `KeySetType::DecompressionOnly` is used

</details>

<details>
    <summary>TypedPlaintext</summary>

### Definition

```proto
message TypedPlaintext {
  bytes bytes = 1;
  FheType fhe_type = 2;
}
```

### Description

Type representing a plaintext and its meta information.

- `bytes`: The little endian encoding of the plaintext.
- `fhe_type`: The enum describing the type of the plaintext.

</details>

<details>
    <summary>TypedCiphertext</summary>

### Definition

```proto
message TypedCiphertext {
  bytes ciphertext = 1;
  FheType fhe_type = 2;
  bytes external_handle = 3;
  CiphertextFormat ciphertext_format = 4;
}
```

### Description

Type representing a ciphertext and its meta information.

- `bytes`: The encoding of the ciphertext.
- `fhe_type`: The enum describing the type of the plaintext encrypted in the ciphertext.
- `external_handle`: The external handle of the ciphertext (the handle used in the coprocessor).
- `ciphertext_format`: An enum representing the format of the ciphertext.

</details>

<details>
    <summary>TypedCiphertext</summary>

### Definition

```proto
message TypedSigncryptedCiphertext {
  FheType fhe_type = 1;
  bytes signcrypted_ciphertext = 2;
  bytes external_handle = 3;
}
```

### Description

Type representing a ciphertext and its meta information.

- `fhe_type`: The enum describing the type of the plaintext encrypted in the ciphertext.
- `signcrypted_ciphertext`: The signcrypted payload, using a hybrid encryption approach in sign-then-encrypt.
- `external_handle`: The external handle of the ciphertext (the handle used in the coprocessor).

</details>

<details>
    <summary>CiphertextFormat</summary>

### Definition

```proto
enum CiphertextFormat {
  SmallCompressed = 0;
  SmallExpanded = 1;
  BigCompressed = 2;
  BigExpanded = 3;
}
```

### Description

Type representing information on the format of a ciphertext.

- `SmallCompressed`: Small (64-bit) compressed ciphertexts, i.e. decompression is needed before it is possible to run the distributed decryption
- `SmallExpanded`: Small (64-bit) expanded ciphertexts.
- `BigCompressed`: Big (128-bit) compressed ciphertexts. WARNING! currently not supported.
- `BigExpanded`: Big (128-bit) expanded ciphertexts. I.e. the 128 bit PBS has already been done.

</details>

## Endpoints (including insecure ones)

## Key Generation

<details>
    <summary> KeyGenPreproc </summary>

### Input

```proto
message KeyGenPreprocRequest {
  FheParameter params = 1;
  KeySetConfig keyset_config = 2;
  RequestId request_id = 3;
}
```

### Output

```proto
message KeyGenPreprocResult {}
```

### Description

This RPC is only relevant in the __threshold__ case.

It triggers the __asynchronous__ correlated randomness generation that is necessary to perform the Distributed Key Generation on the specified `param` using the specific settings of `keyset_config`.

This correlated randomness will then be consumed when calling `KeyGen` with the `preproc_id` set to the current `request_id`.

Observe that this __must__ be completed once before _each_ key generation call.
Completion status can be validated using the `GetKeyGenPreprocResult` endpoint.
</details>

<details>
    <summary> GetKeyGenPreprocResult </summary>

### Input

```proto
message RequestId { string request_id = 1; }
```

### Output

There is no output. If the call is successful then it means preprocessing is completed.
Otherwise, it may fail with the following `tonic::Code` error codes:

- `NotFound`: There has not been a `KeyGenPreproc` call for the provided `request_id`.
- `Unavailable`: The `KeyGenPreproc` for the queried `request_id` has started but is not finished yet.
- `Internal`: The `KeyGenPreproc` for the queried `request_id` has failed due to an internal and unrecoverable server error.

### Description

This RPC allows to check the status of the correlated randomness generation.

Correlated randomness generation is a slow process (several hours), and we thus provide a way to query its status via its unique identifier `request_id`.
This is because, to initiate a Distributed Key Generation, we must provide a `preproc_id` that is the `RequestId` of a `Finished` preprocessing.

The meaning of the enum is as follows:

- `Missing`: There has not been a `KeyGenPreprocRequest` for the provided `request_id`.
- `InProgess`: The core is still generating the correlated randomness for the specified `request_id`.
- `Finished`: The core is done generating the correlated randomness, and we can thus now call `KeyGen` with `preproc_id` set to the current `request_id`.
- `Error`: An irrecoverable internal server error has occurred during the correlated randomness generation.

</details>

<details>
    <summary> KeyGen </summary>

### Input

```proto
message KeyGenRequest {
  FheParameter params = 1;
  RequestId preproc_id = 2;
  RequestId request_id = 3;
  Eip712DomainMsg domain = 4;
  KeySetConfig keyset_config = 5;
  KeySetAddedInfo keyset_added_info = 6;
}
```

### Output

```proto
message Empty {}
```

### Description

This RPC initiates the __asynchronous__ generation of a new TFHE keyset with parameters defined by the provided `params`. The status or result can be retrieved using the `GetKeyGenResult` endpoint.

The `preproc_id` must be the `request_id` of a `Finished` `KeyGenPreprocRequest` in the __threshold__ setting. In the __centralized__ setting, this can be ignored.
The `keyset_config` is the information about the keys to generate and _must_ match the similar argument used during preprocessing in `KeyGenPreprocRequest`.
The `keyset_added_info` contains the relevant `RequestId`s for key(s) needed to generate the key switching key.

All the public material produced during this key generation will be EIP712-signed using the core's private key and the provided `domain` as `Eip712Domain`. This EIP712 signature is referred to as the `external_signature`.

</details>

<details>
    <summary> GetKeyGenResult </summary>

### Input

```proto
message RequestId { string request_id = 1; }
```

### Output

```proto
message KeyGenResult {
  RequestId request_id = 1;
  map<string, SignedPubDataHandle> key_results = 2;
}
```

### Description

This RPC allows to retrieve the status or result of the generation of public key material when `request_id` has been used in a`KeyGen` call.

Because this call is dependent on previous call, it may fail with the following `tonic::Code` error codes:

- `NotFound`: There has not been a `KeyGen` call for the provided `request_id`.
- `Unavailable`: The `KeyGen` for the queried `request_id` has started but is not finished yet.
- `Internal`: The `KeyGen` for the queried `request_id` has failed due to an internal and unrecoverable server error.

If the call is successful, the `KeyGenResult` will contain the `request_id` used in the query, as well as the following map:

- Key: `"PublicKey"`, Value: The `SignedPubDataHandle` corresponding to the generated `tfhe::CompactPublicKey`.
- Key: `"ServerKey"`, Value: The `SignedPubDataHandle` corresponding to the generated `tfhe::ServerKey`.
- __If the setting is threshold__ Key: `"SnsKey"`, Value: The `SignedPubDataHandle` corresponding to the generated `SwitchAndSquashKey`.

</details>

<details>
    <summary> InsecureKeyGen </summary>

___NOTE_: This is a temporary workaround and will only be available in testing/debugging setups. **NOT in production**__

### Input

```proto
message KeyGenRequest {
  FheParameter params = 1;
  RequestId preproc_id = 2;
  RequestId request_id = 3;
  Eip712DomainMsg domain = 4;
  KeySetConfig keyset_config = 5;
  KeySetAddedInfo keyset_added_info = 6;
}
```

### Output

```proto
message Empty {}
```

### Description

Insecure version of `KeyGen`, where MPC is _not_ used for key generation.
This RPC initiates the __asynchronous__ generation of a new TFHE keyset with parameters defined by the provided `params`. The status or result can be retrieved using the `GetKeyGenResult` or `GetInsecureKeyGenResult` endpoint.

The `preproc_id` can be ignored.

The `keyset_config` is the information about the keys to generate.
The `keyset_added_info` contains the relevant `RequestId`s for key(s) needed to generate the key switching key.

All the public material produced during this key generation will be EIP712-signed using the core's private key and the provided `domain` as `Eip712Domain`. This EIP712 signature is referred to as the `external_signature`.
</details>

<details>
    <summary> GetInsecureKeyGenResult </summary>

```proto
message RequestId { string request_id = 1; }
```

### Output

```proto
message KeyGenResult {
  RequestId request_id = 1;
  map<string, SignedPubDataHandle> key_results = 2;
}
```

### Description

This RPC allows to retrieve the public key material if the `request_id` is that of a finished `KeyGen`.

Because this call is dependent on previous call, it may fail with the following `tonic::Code` error codes:

- `NotFound`: There has not been a `KeyGen` call for the provided `request_id`.
- `Unavailable`: The `KeyGen` for the queried `request_id` has started but is not finished yet.
- `Internal`: The `KeyGen` for the queried `request_id` has failed.

If the call is successful, the `KeyGenResult` will contain the `request_id` used in the query, as well as the following map:

- Key: `"PublicKey"`, Value: The `SignedPubDataHandle` corresponding to the generated `tfhe::CompactPublicKey`.
- Key: `"ServerKey"`, Value: The `SignedPubDataHandle` corresponding to the generated `tfhe::ServerKey`.
- __If the setting is threshold__ Key: `"SnsKey"`, Value: The `SignedPubDataHandle` corresponding to the generated `SwitchAndSquashKey`.

Functionally this call is similar to `GetKeyGenResult`.
</details>

## CRS Generation

<details>
    <summary> CrsGen </summary>

### Input

```proto
message CrsGenRequest {
  FheParameter params = 1;
  optional uint32 max_num_bits = 2;
  RequestId request_id = 3;
  Eip712DomainMsg domain = 4;
}
```

### Output

```proto
message Empty {}
```

### Description

This RPC initiates the __asynchronous__ generation of a new CRS defined by the provided `params` and `max_num_bits`. Here, `max_num_bits` is the maximum number of bits that can be proven in one go (i.e. 64 bits are required to prove a single `FheUint64`).
If no value is given for `max_num_bits`, it defaults to `2048`.

The status or result of this call can be retrieved with the `GetCrsGenResult` endpoint.
The CRS produced during the generation will be EIP712-signed using the KMS core's private key and the provided `domain` as `Eip712Domain`. This `EIP712` signature is referred to as the `external_signature`.
</details>

<details>
    <summary> GetCrsGenResult </summary>

### Input

```proto
message RequestId { string request_id = 1; }
```

### Output

 ```proto
 message CrsGenResult {
  RequestId request_id = 1;
  SignedPubDataHandle crs_results = 2;
}
 ```

### Description

This RPC allows to retrieve the CRS if the `request_id` is that of a successfully completed `CrsGen` call.

Because this call is dependent on previous call, it may fail with the following `tonic::Code` error codes:

- `NotFound`: There has not been a `CrsGen` call for the provided `request_id`.
- `Unavailable`: The `CrsGen` for the queried `request_id` has started but is not finished yet.
- `Internal`: The `CrsGen` for the queried `request_id` has failed.

If the call is successful, the `CrsGenResult` will contain the `request_id` used in the query, as well as a `SignedPubDataHandle` that corresponds to the generated `tfhe_zk_pok::proofs::pke::PublicParams<tfhe_zk_pok::curve_api::Bls12_446>`.

</details>

## Public Decryption

<details>
    <summary> PublicDecryption </summary>

### Input

```proto
message PublicDecryptionRequest {
  repeated TypedCiphertext ciphertexts = 1;
  RequestId key_id = 2;
  Eip712DomainMsg domain = 3;
  RequestId request_id = 4;
}


message TypedCiphertext {
  bytes ciphertext = 1;
  FheType fhe_type = 2;
  optional bytes external_handle = 3;
  CiphertextFormat ciphertext_format = 4;
}

```

### Output

```proto
message Empty {}
```

### Description

This RPC initiates the __asynchronous__ public decryption of the provided `ciphertexts`.
The status or result can be retrieved with a call to the `GetDecryptResult` endpoint.

It expects:

- `ciphertexts`: an array of the `TypedCiphertext`s (described below) to decrypt.
- `key_id`: the `RequestId` that corresponds to the TFHE key the ciphertexts are encrypted under.
- `request_id`: A unique uint256 RequestId for the decryption request.
- `domain`: EIP712 domain information which will be used when signing the decrypted plaintext.

Each ciphertext to be decrypted comes accompanied by some metadata in the `TypedCiphertext` structure:

- `ciphertext` is the `tfhe::safe_serialize` ciphertext. We support both safe serialized `tfhe::CompressedCiphertextList` or `FheUint` types.
- `fhe_type` is the type of the ciphertext (e.g. `FheUint8`)
- `external_handle`: The hex encoded handle identifying the ciphertext on the _main_ L1 chain.
- `ciphertext_format`: An enum expressing the form of the ciphertext given as input.

The response will be EIP712-signed using the KMS core's private key and the provided `domain` as `Eip712Domain`. The `EIP712` signature is referred to as the `external_signature`.
</details>

<details>
    <summary> PublicDecryptionResponse </summary>

### Input

```proto
message RequestId { string request_id = 1; }
```

### Output

```proto
message PublicDecryptionResponse {
  bytes signature = 1;
  PublicDecryptionResponsePayload payload = 2;
}

message PublicDecryptionResponsePayload {
  bytes verification_key = 1;
  bytes digest = 2;
  repeated TypedPlaintext plaintexts = 3;
  optional bytes external_signature = 4;
}

```

### Description

This RPC allows to retrieve the plaintexts if the `request_id` is that of a finished `PublicDecryption`.

The `signature` is a `secp256k1` signature on the `bincode::serialize` of the `payload` using the core's private key.

#### The `payload` is composed of

- `verification_key`: the `bincode::serialize` `ECDSA/secp256k1` verification key of the core.
- `digest`: The 256 bits `SHAKE-256` digest of the corresponding `bincode::serialize` `PublicDecrypt` request.
- `plaintexts`: An array of plaintexts and their meta information that are the requested decryptions.
- `external_signature`: The `EIP-712` signature on the encoding of the uint256 handles of the ciphertexts, concatenated with big endian encoding of the `TypedPlaintext`s using the KMS core's private key.

</details>

## Key Material Availability

<details>
    <summary> GetKeyMaterialAvailability </summary>

### Input

```proto
message Empty {}
```

### Output

```proto
message KeyMaterialAvailabilityResponse {
  repeated string fhe_key_ids = 1;
  repeated string crs_ids = 2;
  repeated string preprocessing_ids = 3;
  string storage_info = 4;
}
```

### Description

This RPC provides a comprehensive view of all available key material in the KMS, including FHE keys, CRS keys, and preprocessing material (threshold KMS only).

The response contains:

- `fhe_key_ids`: List of all available FHE key IDs (request IDs from KeyGen operations)
- `crs_ids`: List of all available CRS key IDs (request IDs from CrsGen operations)  
- `preprocessing_ids`: List of all available preprocessing material IDs (request IDs from KeyGenPreproc operations in threshold KMS, empty for centralized KMS)
- `storage_info`: Diagnostic information about the storage backend (e.g., "Centralized KMS" or "Threshold KMS")

This endpoint is useful for:
- Health checks and monitoring
- Verifying key material availability before operations
- Debugging and diagnostics
- CI/CD integration

The endpoint queries the underlying storage directly and returns immediately with the current state.

</details>

## Health Status

<details>
    <summary> GetHealthStatus </summary>

### Input

```proto
message Empty {}
```

### Output

```proto
// Health status levels
enum HealthStatus {
  HEALTH_STATUS_UNSPECIFIED = 0;
  HEALTH_STATUS_HEALTHY = 1;
  HEALTH_STATUS_DEGRADED = 2;
  HEALTH_STATUS_UNHEALTHY = 3;
}

// Node type for KMS deployment
enum NodeType {
  NODE_TYPE_UNSPECIFIED = 0;
  NODE_TYPE_CENTRALIZED = 1;
  NODE_TYPE_THRESHOLD = 2;
}

message HealthStatusResponse {
  // Overall health status
  HealthStatus status = 1;
  
  // Health information for a peer node
  message PeerHealth {
    // Peer party ID (for threshold mode)
    uint32 peer_id = 1;
    
    // Peer endpoint address
    string endpoint = 2;
    
    // Whether the peer is reachable
    bool reachable = 3;
    
    // Connection latency in milliseconds
    uint32 latency_ms = 4;
    
    // Storage info from peer
    string storage_info = 5;
    
    // Error message if peer is unreachable
    string error = 6;
    
    // Key IDs for FHE keys on peer (when available)
    repeated string fhe_key_ids = 7;
    
    // Key IDs for CRS keys on peer (when available)
    repeated string crs_ids = 8;
    
    // Key IDs for preprocessing keys on peer (when available)
    repeated string preprocessing_key_ids = 9;
  }
  
  // Health status of all peers
  repeated PeerHealth peers = 2;
  
  // Self key material IDs
  repeated string my_fhe_key_ids = 3;
  repeated string my_crs_ids = 4;
  repeated string my_preprocessing_key_ids = 5;
  string my_storage_info = 6;
  
  // Runtime configuration info
  NodeType node_type = 7;
  uint32 my_party_id = 8; // Only for threshold mode
  uint32 threshold_required = 9; // Minimum nodes needed
  uint32 nodes_reachable = 10; // Currently reachable nodes
}
```

### Description

This RPC provides comprehensive health status information for the KMS instance, including connectivity to peers (threshold mode only), key material counts, and overall system health.

The response contains:

- `status`: Overall health assessment using HealthStatus enum (HEALTH_STATUS_HEALTHY, HEALTH_STATUS_DEGRADED, or HEALTH_STATUS_UNHEALTHY)
- `peers`: Detailed health information for each peer in threshold mode, including:
  - Connectivity status and latency
  - Actual key IDs for FHE keys, CRS keys, and preprocessing material (when available)
  - Storage backend information
  - Error details if unreachable
- `my_*` fields: Self key material IDs and storage information
- Configuration details: node type (NodeType enum), party ID, threshold requirements, and reachable node count

Health status levels:
- **Healthy**: All checks passed, keys present, all required peers reachable
- **Degraded**: Service operational but with issues (missing keys, some peers unreachable, warnings)
- **Unhealthy**: Critical issues (cannot connect, invalid config, insufficient nodes for threshold)

This endpoint is useful for:
- Health monitoring and alerting
- Load balancer health checks
- Kubernetes readiness/liveness probes
- Debugging connectivity issues
- Operational dashboards

The endpoint performs real-time connectivity checks to peers and returns current system status.

**Implementation Notes:**
- Self key material is retrieved directly from internal storage components (no redundant gRPC calls)
- Peer key material is fetched via gRPC calls to each peer's health endpoint
- Preprocessing key IDs are included for threshold nodes when available from the keygen preprocessor
- Storage backend information provides visibility into the underlying storage type (file, RAM, S3)

</details>

## User Decryption

<details>
    <summary> UserDecryption </summary>

### Input

```proto
message UserDecryptionRequest {
  UserDecryptionRequestPayload payload = 1;
  Eip712DomainMsg domain = 2;
  RequestId request_id = 3;
}


message UserDecryptionRequestPayload {
  string client_address = 1;
  bytes enc_key = 2;
  RequestId key_id = 3;
  repeated TypedCiphertext typed_ciphertexts = 4;
}
```

### Output

```proto
message Empty {}
```

### Description

This RPC initiates the __asynchronous__ user decryption of the provided `ciphertext`.
Meaning that a specified ciphertext will get _privately_ decrypted and encrypted under a specified non-homomorphic public key.
The process ensures that no-one (even the MPC parties) learn the decrypted value unless they know the private decryption key for the non-homomorphic public key.

It expects:

- `payload`: the `UserDecryptionRequestPayload` described below.
- `domain`: EIP712 domain information which will be used when signing the decrypted plaintext.
- `request_id`: A unique uint256 RequestId for the decryption request.

The `UserDecryptionRequestPayload` contains all the information necessary to perform the user decryption:

- `client_address`: An EIP-55 encoded address (including the `0x` prefix) of the end-user who is supposed to learn the user decryption response.
- `enc_key`: The `bincode::serialize` of `PublicEncKey`, which is a wrapper around a `crypto_box::PublicKey` to be used for encrypting the result.
- `key_id`: The `RequestId` of the TFHE key the ciphertext is encrypted under.
- `typed_ciphertext`: The ciphertexts to decrypt and their meta information.

The response will be EIP712-signed using the KMS core's private key and the provided `domain` as `Eip712Domain`. The `EIP712` signature is referred to as the `external_signature`.
</details>

<details>
    <summary> UserDecryptionResponse </summary>

### Input

```proto
message RequestId { string request_id = 1; }
```

### Output

```proto
message UserDecryptionResponse {
  bytes signature = 1;
  UserDecryptionResponsePayload payload = 2;
}

message UserDecryptionResponsePayload {
  bytes verification_key = 1;
  bytes digest = 2;
  repeated TypedSigncryptedCiphertext signcrypted_ciphertexts = 3;
  uint32 party_id = 4;
  uint32 degree = 5;
  bytes external_signature = 6;
}
```

### Description

This RPC allows to retrieve the user decrypted plaintext if the `request_id` is that of a finished `UserDecrypt`.

The signature is a `secp256k1` signature on the `bincode::serialize` of the `payload` using the core's private key.

#### The `payload` is composed of

- `verification_key`: the `bincode::serialize` `ECDSA/secp256k1` verification key of the core.
- `digest`: The concatenation of two digests `(eip712_signing_hash(pk, domain) || ciphertext digest)`
- `party_id`: The MPC ID of the KMS core party doing the user decryption. Necessary for doing the share reconstruction.
- `degree`: The degree of the sharing scheme used. Necessary for doing the share reconstruction.
- `external_signature`: a `EIP-712` signature on the _solidity-compatible_  256 bits `SHAKE-256` hash of the `tfhe::safe_serialization` of the underlying struct.

</details>
