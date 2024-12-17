<p align="center">
<!-- product name logo -->
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="KMS-dark.png">
  <source media="(prefers-color-scheme: light)" srcset="KMS-light.png">
  <img width=600 alt="Zama KMS">
</picture>
</p>


<p align="center">
  <a href=""> 📒 White paper</a> | <a href="https://github.com/zama-ai/kms-whitepaper"> 📚 The KMS Whitepaper by Zama</a>
</p>


<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-BSD--3--Clause--Clear-%23ffb243?style=flat-square"></a>
  <a href="https://github.com/zama-ai/bounty-program"><img src="https://img.shields.io/badge/Contribute-Zama%20Bounty%20Program-%23ffd208?style=flat-square"></a>
</p>

## About

### Status
[![CI](https://github.com/zama-ai/kms/workflows/CI/badge.svg)](https://github.com/zama-ai/kms/actions)
[![image-badge](https://ghcr-badge.egpl.dev/zama-ai/kms/tags?trim=major)](https://github.com/zama-ai/kms/pkgs/container/kms)
[![image-size-badge](https://ghcr-badge.egpl.dev/zama-ai/kms/size)](https://github.com/zama-ai/kms/pkgs/container/kms)
[![license-badge](https://img.shields.io/badge/License-BSD-blue)](LICENSE)


### What is KMS
The Zama KMS is a fully decentralized key management solution for TFHE, more specifically [TFHE-rs](https://github.com/zama-ai/tfhe-rs), based on a maliciously secure and robust [MPC protocol](https://eprint.iacr.org/2023/815).

The system facilitates this through the use of a blockchain which provides a means of fulfilling payments to the MPC parties, along with providing an immutable audit log.

Interaction with the same KMS will happen either through an external Ethereum blockchain, providing an API via a smart contract, or through a gateway service.

### Main features
The following describes how the KMS is used in conjunction with an fhEVM blockchain, including the external components needed.
While the KMS can be used with multiple fhEVMs, for simplicity, we will in the following document assume there is only a single fhEVM.

At the highest level, the system consists of two subsystems: an *fhEVM blockchain* and a *KMS*. The KMS in turn consists of a *KMS blockchain* and a *KMS core*. These are in turn composed of the following components, which we illustrate in the pictures below where we use conjoined boxes to mean that components are part of the same Docker image.
![Centralized KMS system](central.png "Centralized KMS system")
![Threshold KMS system](threshold.png "Threshold KMS system")

We now briefly outline each of these components along with their constituents:

- *fhEVM validator*: The validator node running the fhEVM blockchain.

- *Gateway*: Untrusted service that listens for decryption events on the fhEVM blockchain and propagates these as decryption requests to the KMS, and propagates decryption results back to the fhEVM blockchain. Used in a similar fashion to handle reencryption requests from a user.

- *Gateway KMS Connector*: A simple translation service that offers a gRPC interface for the gateway to communicate with the KMS blockchain. Calls from the gateway are submitted as transactions to the KMS blockchain, and result events from the KMS blockchain are returned to the gateway.

- *KV-store*: A simple storage service that holds the actual FHE ciphertexts on behalf of the KMS blockchain (which instead stores a hash digest of the ciphertext).

- *KMS Validator*: The validator node running the KMS blockchain.

- *KMS Connector*: A simple translation service that listens for request events from the KMS blockchain and turn these into gRPC calls to the KMS Core. Likewise, results from the KMS Core are submitted as transactions back to the KMS blockchain.

- *KMS Core*: Trusted gRPC service that implements the actual cryptographic operations such as decryption and reencryption. All results are signed.

On the fhEVM blockchain the following smart contracts are deployed:

- *ACL smart contract*: Smart contract deployed on the fhEVM blockchain to manage access control of ciphertexts. dApp contracts use this to persists their own access rights and to delegate access to other contracts.

- *Gateway smart contract*: Smart contract deployed on the fhEVM blockchain that is used by a dApp smart contract to request a decrypt. This emits an event that triggers the gateway.

- *KMS smart contract*: Smart contract running on the fhEVM blockchain that is used by a dApp contract to verify decryption results from the KMS. To that end, it contains the identity of the KMS and is used to verify its signatures.

On the KMS blockchain the following smart contracts are deployed:

- *fhEVM ASC*: Smart contract to which transaction from the gateway (connector) are submitted to. This contract contains all customization logic required to work with the specific fhEVM blockchain.

Finally, dApp smart contracts use the *TFHE* Solidity library to perform operations on encrypted data on the fhEVM blockchain. This library is embedded into the dApp smart contract, and calls an executor smart contract under the hood.

### Implementation

The KMS is implemented as a gRPC service using the [tonic](https://github.com/hyperium/tonic) crate.
Communication between full nodes and the KMS service is defined by [protobuf](/proto/kms.proto) messages.
The rest of the communication is defined by existing standards and uses JSON-RPC.
For the light client, we currently use CometBFT's [light](https://pkg.go.dev/github.com/cometbft/cometbft/light) package, which provides a service that connects to any CometBFT full node to serve trusted state roots on-demand.
The light client package handles the logic of sequentially verifying block headers.

## Installation
Docker images that is ready for use can be found [here](https://github.com/orgs/zama-ai/packages).

## Getting started
The project requires the use of Docker and Rust. Ensure that these are installed on your system.

The project can be build with:
```
cargo build
```

Testing can be done using
```
cargo test
```
Some integration tests may require the use of additional tools. Further details can be found in the READMEs in each sub project. To avoid them and only run unit tests, run the following command instead: 
```
cargo test --lib
```

> **_NOTE:_** You might need to set the `rustc` version to use the nightly build to avoid issues with experimental features. To do so launch the following command.
```
rustup override set nightly
```


### Development Environment

Read this [section](./config/dev/README.md) for more information.

### Release

Read this [section](./docs/ci/release.md) for more information.


### A simple example
For an example of usage consult the [technical specification](https://github.com/zama-ai/tech-spec/tree/main/kms).


## Resources

### Theory
- [Noah's Ark: Efficient Threshold-FHE Using Noise Flooding](https://eprint.iacr.org/2023/815)

### Whitepaper
- [KMS Whitepaper](https://github.com/zama-ai/kms-whitepaper)

### Technical specification
- [Tech spec](https://github.com/zama-ai/tech-spec/tree/main/kms)

### Docker images and high level usage
- [fhEVM integration](https://github.com/zama-ai/fhevm-L1-demo)

## Working with KMS

### Disclaimers

#### Audits
The Zama KMS is not yet audited and should be considered in the early alpha stage. Known bugs and security issues are present as reflected by issue tracking.

#### Parameters
The default parameters for the Zama KMS are chosen to ensure a failure probability of 2^-64 and symmetric equivalent security of 128 bits.

#### Side-channel attacks

Mitigation for side-channel attacks has not been implemented directly in the Zama KMS. The smart contract of the blockchain from which calls originate is responsible to ensure the validity of calls. In particular that new ciphertexts are correctly constructed (through a proof-of-knowledge).

### Citations
To cite KMS in academic papers, please use the following entry:
```
@Misc{zama-kms,
  title={{Zama KMS: A Pure Rust Implementation of a Threshold Key Management System for TFHE}},
  author={Zama},
  year={2024},
  note={\url{https://github.com/zama-ai/kms-core}},
}
```

### License
This software is distributed under the **BSD-3-Clause-Clear** license. Read [this](LICENSE.txt) for more details.

#### FAQ
**Is Zama’s technology free to use?**
>Zama’s libraries are free to use under the BSD 3-Clause Clear license only for development, research, prototyping, and experimentation purposes. However, for any commercial use of Zama's open source code, companies must purchase Zama’s commercial patent license.
>
>Everything we do is open source and we are very transparent on what it means for our users, you can read more about how we monetize our open source products at Zama in [this blog post](https://www.zama.ai/post/open-source).

**What do I need to do if I want to use Zama’s technology for commercial purposes?**
>To commercially use Zama’s technology you need to be granted Zama’s patent license. Please contact us hello@zama.ai for more information.

**Do you file IP on your technology?**
>Yes, all Zama’s technologies are patented.

**Can you customize a solution for my specific use case?**
>We are open to collaborating and advancing the FHE space with our partners. If you have specific needs, please email us at hello@zama.ai.


## Support

<a target="_blank" href="https://community.zama.ai">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://github.com/zama-ai/tfhe-rs/assets/157474013/08656d0a-3f44-4126-b8b6-8c601dff5380">
  <source media="(prefers-color-scheme: light)" srcset="https://github.com/zama-ai/tfhe-rs/assets/157474013/1c9c9308-50ac-4aab-a4b9-469bb8c536a4">
  <img alt="Support">
</picture>
</a>

🌟 If you find this project helpful or interesting, please consider giving it a star on GitHub! Your support helps to grow the community and motivates further development.
