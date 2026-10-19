# Engine Module

This folder contains the core logic for the Key Management Service (KMS) server, focusing on the implementation of gRPC endpoints for cryptographic operations such as key generation and decryption.

## Structure

- **base.rs**  
  Universal code for the gRPC service structure, providing shared logic and abstractions used by the threshold service. That is, the structs and universal methods used to define a KMS server.

- **context.rs**  
  Definitions and utilities for managing the service context, including state and configuration relevant to KMS operations.

- **context_manager.rs**: Management of MPC contexts and custodian contexts.

- **server.rs**  
  Main server implementation for handling incoming gRPC requests.

- **traits.rs**  
  Common traits and interfaces used throughout the engine module.

- **validation_non_wasm.rs / validation_wasm.rs**  
  Validation logic for different build targets (native and WASM). Observe that the WASM build is _only_ used for user decryption.

### KMS services

- **kms.rs**: Main implementation for threshold (distributed) KMS logic.

- **endpoint.rs**  
  Entry points for threshold gRPC calls.

- **service_traits.rs**: Traits specific to threshold services.

- **service/**  
  Endpoint-specific code for threshold operations:
  - **crs_generator.rs**: CRS generation logic.
  - **key_generator.rs**: Key generation logic.
  - **kms_impl.rs**: Core threshold KMS implementation.
  - **preprocessor.rs**: Key generation pre-processing.
  - **public_decryptor.rs**: Public decryption logic.
  - **session.rs**: Session management.
  - **user_decryptor.rs**: User decryption logic.
  - **mod.rs**: Module declarations for threshold service.

## Purpose

The `engine` module acts as the backbone of the KMS server, exposing cryptographic functionality via gRPC endpoints. It implements threshold (distributed) key management.

## Usage

This module is not intended to be used directly. Instead, it is integrated into the overall KMS server binary, which initializes the appropriate services and exposes the gRPC API to clients.


## Expanding

To expand the module add relevant structures and/or functions to the protobuf files (found in `../../../grpc/proto/*`).
Then compile to generate the protobuf fixtures and add the new methods to `endpoint.rs`.

---

For more details on specific endpoints and usage, refer to the documentation within each submodule.
