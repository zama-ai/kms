# Engine Module

This folder contains the core logic for the Key Management Service (KMS) server, focusing on the implementation of gRPC endpoints for cryptographic operations such as key generation and decryption.

## Structure

- **base.rs**  
  Universal code for the gRPC service structure, providing shared logic and abstractions used by both centralized and threshold services. That is, the structs and universal methods used to define a KMS server.

- **context.rs**  
  Definitions and utilities for managing the service context, including state and configuration relevant to KMS operations.

- **server.rs**  
  Main server implementation for handling incoming gRPC requests.

- **traits.rs**  
  Common traits and interfaces used throughout the engine module.

- **validation_non_wasm.rs / validation_wasm.rs**  
  Validation logic for different build targets (native and WASM). Observe that the WASM build is _only_ used for user decryption.

### Centralized KMS (`centralized/`)

- **central_kms.rs**  
  Core logic for centralized key management.

- **endpoint.rs**  
  Entry points for centralized gRPC calls (now at the root of the `centralized` folder).

- **service/**  
  Endpoint-specific code for centralized operations:
  - **context.rs**: Service context management.
  - **crs_gen.rs**: CRS generation logic.
  - **decryption.rs**: Decryption endpoint logic.
  - **key_gen.rs**: Key generation endpoint logic.
  - **mod.rs**: Module declarations for centralized service.

### Threshold KMS (`threshold/`)

- **threshold_kms.rs**  
  Main implementation for threshold (distributed) KMS logic (renamed from `generic.rs`).

- **threshold_kms_mock.rs**  
  Mock services for testing threshold KMS.

- **endpoint.rs**  
  Entry points for threshold gRPC calls.

- **traits.rs**  
  Traits specific to threshold services.

- **service/**  
  Endpoint-specific code for threshold operations:
  - **context_manager.rs**: Service context management.
  - **crs_generator.rs**: CRS generation logic.
  - **initiator.rs**: Session initiator logic.
  - **key_generator.rs**: Key generation logic.
  - **kms_impl.rs**: Core threshold KMS implementation.
  - **preprocessor.rs**: Key generation pre-processing.
  - **public_decryptor.rs**: Public decryption logic.
  - **session.rs**: Session management.
  - **user_decryptor.rs**: User decryption logic.
  - **mod.rs**: Module declarations for threshold service.

## Purpose

The `engine` module acts as the backbone of the KMS server, exposing cryptographic functionality via gRPC endpoints. It supports both centralized and threshold (distributed) key management, allowing for flexible deployment in various security architectures.

## Usage

This module is not intended to be used directly. Instead, it is integrated into the overall KMS server binary, which initializes the appropriate services and exposes the gRPC API to clients.


## Expanding

To expand the module add relevant structures and/or functions to the protobuf files (found in `../../../grpc/proto/*`).
Then compile to generate the protobuf fixtures and add the new methods to `centralized/endpoint.rs`, respecitvely `threshold/endpoint.rs`.

---

For more details on specific endpoints and usage, refer to the documentation within each submodule.
