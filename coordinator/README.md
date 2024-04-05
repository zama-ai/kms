# Key Management System

[![CI](https://github.com/zama-ai/kms/workflows/CI/badge.svg)](https://github.com/zama-ai/kms/actions)
[![image-badge](https://ghcr-badge.egpl.dev/zama-ai/kms/tags?trim=major)](https://github.com/zama-ai/kms/pkgs/container/kms)
[![image-size-badge](https://ghcr-badge.egpl.dev/zama-ai/kms/size)](https://github.com/zama-ai/kms/pkgs/container/kms)
[![license-badge](https://img.shields.io/badge/License-BSD-blue)](LICENSE)


https://github.com/zama-ai/kms/actions/workflows/publish-docker-image.yml

This repository hosts the code for the Zama Key Management System prototypes.


## MVP Specification

The full KMS specification is currently under review. What follows describes a KMS minimal viable product.

### Description
It is assumed that neither decryptions nor reencryptions happen during transactions. Instead, transactions *mark* ciphertexts as decryptable or reencryptable.
Subsequently, full nodes may issue decryption and reencryption requests to the KMS for ciphertexts which have been marked as decryptable or reencryptable. Usually, this happens upon reception of a request from a user or wallet.

### Sequence Diagram (reencryption)

```mermaid
sequenceDiagram
    actor Wallet
    Wallet->>+Full Node: View function request
    Full Node->>Full Node: Execute view function (encounter `TFHE.reencrypt(ct, pubkey)`)
    Full Node->>Full Node: Generate `proof` for {`ct`, `pubkey`}
    Full Node->>+KMS: Reencryption request ({`ct`, `pubkey`, `proof`, `height`})
    KMS->>+Light Client: Get state root at height `height`
    Light Client->>-KMS: `root`
    KMS->>KMS: Verify `proof` against `root`
    KMS->>KMS: Decrypt
    KMS->>KMS: Encrypt result under `pubkey`
    KMS->>KMS: Sign encrypted result
    KMS->>-Full Node: {`reencryped_ciphertext`, `sig`}
    Full Node->>Full Node: Verify `sig`
    Full Node->>-Wallet: `reencryped_ciphertext`
    Wallet->>Wallet: Decrypt
```
The process for decryptions is analogous.

For the time being, the light client is assumed to provide valid state roots to the KMS service.

In practice, the light client relies on any full node that is live and up to date with the blockchain.
Once the trusted setup is done at genesis, the light client can be trusted to provide valid state roots for any block, as long as the full node it connects to does not engage in byzantine behavior.

## Implementation

The KMS is iplemented as a gRPC service using the [tonic](https://github.com/hyperium/tonic) crate.
Communication between full nodes and the KMS service is defined by [protobuf](/proto/kms.proto) messages.
The rest of the communication is defined by existing standards and uses JSON-RPC.
For the light client, we currently use CometBFT's [light](https://pkg.go.dev/github.com/cometbft/cometbft/light) package, which provides a service that connects to any CometBFT full node to serve trusted state roots on-demand.
The light client package handles the logic of sequentially verifying block headers.

## Next steps
- [ ] Full Node ->> KMS Reencryption request should contain user signature on `pubkey` and an `ACL` object.
- [ ] KMS should verify the user signature on `pubkey` against the values of permissible decryptors in `ACL`.


## Contribution

See [CONTRIBUTING.md](CONTRIBUTING.md).


