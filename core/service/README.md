# Zama Key Management System

This folder hosts the code for the KMS Core service, which provides externally-facing gRPC endpoints to use the Zama KMS.
Detailed information about usage, along with sequence diagrams, can be found [here](https://github.com/zama-ai/tech-spec/tree/main/architecture), while information about the MPC protocols utilized can be found in [this paper](https://eprint.iacr.org/2023/815). The FHEVM whitepaper, which is the main application using the KMS, can be found [here](https://github.com/zama-ai/fhevm-whitepaper).

## Implementation

The KMS is implemented as a gRPC service using the [tonic](https://github.com/hyperium/tonic) crate.
Communication between full nodes and the KMS service is defined by [protobuf](/proto/kms.proto) messages.
The rest of the communication is defined by existing standards and uses JSON-RPC.

Optionally, the gRPC service can be run in an Amazon Nitro enclave and store sensitive key material encrypted on S3.

### Directory overview
- `config`
    - Default and example configuration files used when running the Core Service.
- [`src/bin`](./src/bin/README.md)
    - Code used to compile binary files. This includes the actual KMS Core Service, but also utilities needed for generating TLS certificates for the KMS Core servers.
- `src/client`
    - Example client code which is primarily used for testing the KMS Core.
- `src/conf`
    - Configuration files for running the KMS Core(s).
- `src/cryptography`
    - Folder containing PKE cryptography code, along with cryptography needed to interface with tfhe-rs.
- `src/engine`
    - Folder containing the actual code implementing the KMS Core service.
- `src/util`
    - Folder containing utility code such as for file management and network management.
- `src/vault`
    - Folder containing code for file storage management and Nitro enclave and AWS KMS integration.
- `tests`
    - Code for backwards compatibility and integration testing.

## Compiling and running
Information about the compiling and running the KMS Core service can be found [here](./src/bin/README.md).
Details on how to interact with a running KMS Core service can be found [here](../../core-client/README.md).

## Contribution

See [CONTRIBUTING.md](CONTRIBUTING.md).
