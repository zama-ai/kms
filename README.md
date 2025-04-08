<p align="center">
<!-- product name logo -->
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="KMS-dark.png">
  <source media="(prefers-color-scheme: light)" srcset="KMS-light.png">
  <img width=600 alt="Zama KMS">
</picture>
</p>


<p align="center">
  <a href="https://github.com/zama-ai/httpz-whitepaper"> 📒 HTTPZ White paper</a> | <a href="https://eprint.iacr.org/2023/815"> 📚 Noah's Ark (peer-reviewed academic paper)</a>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-BSD--3--Clause--Clear-%23ffb243?style=flat-square"></a>
  <a href="https://github.com/zama-ai/bounty-program"><img src="https://img.shields.io/badge/Contribute-Zama%20Bounty%20Program-%23ffd208?style=flat-square"></a>
</p>

## About

### Status
[![CI](https://github.com/zama-ai/kms-core/actions/workflows/service-main.yml/badge.svg)](https://github.com/zama-ai/kms-core/pkgs/container/kms-service)
[![image-badge](https://ghcr-badge.egpl.dev/zama-ai/kms-service/tags?trim=major)](https://github.com/zama-ai/kms-core/pkgs/container/kms-service)
[![image-size-badge](https://ghcr-badge.egpl.dev/zama-ai/kms-service/size)](https://github.com/zama-ai/kms-core/pkgs/container/kms-service)
[![license-badge](https://img.shields.io/badge/License-BSD-blue)](LICENSE)


### What is KMS
The Zama KMS is a fully decentralized key management solution for TFHE, more specifically [TFHE-rs](https://github.com/zama-ai/tfhe-rs), based on a maliciously secure and robust [MPC protocol](https://eprint.iacr.org/2023/815).

The system facilitates this through the use of a blockchain which provides a means of fulfilling payments to the MPC parties, along with providing an immutable audit log.

Interaction with the same KMS will happen either through an external Ethereum blockchain, providing an API via a smart contract, or through the [HTTPZ gateway service](https://github.com/zama-ai/gateway-l2).

### Main features
The following describes how the KMS is used in conjunction with HTTPZ Gateway, including the external components needed.
While the KMS can be used with multiple L1 EVM host chains, for simplicity, we will in the following document assume there is only a single L1 host chain.

At the highest level, the system consists of multiple subsystems: a *host chain*, an *HTTPZ Gateway* and a *KMS*. The KMS is in turn composed of the following components, which we illustrate in the pictures below.

![KMS system](./docs/getting-started/overview.png)

We observe that while the standard deployment of the KMS system is in a threshold setting. It can also be deployed in a centralized manner, where it will consist of a single logical Connector, Core and Keychain DA.
For more details we direct the reader to [the architecture section](https://github.com/zama-ai/tech-spec/tree/main/architecture) of the tech spec.

### Implementation

The KMS is implemented as a gRPC service using the [tonic](https://github.com/hyperium/tonic) crate.
Communication to the KMS Core service is done using gRPC and is defined by [protobuf](./core/grpc/proto/) messages.
The rest of the communication is defined by existing standards and uses JSON-RPC.

### Directory overview
- [`backwards-compatibility`](./backward-compatibility/README.md)
    - Code needed for testing upgrade compatibility of the system. I.e. ensures any internal format upgrade can be gracefully handled. Not used in production.
- `ci`
    - Code related to Continuous Integration (CI). Observe that specific CI scripts for the Github CI can be found in the `.github` folder.
- `common`
    - Utility code and macros shared between other source code folders.
- [`conf-trace`](./conf-trace/README.md)
    - Code and documentation related to open telemetry tracing; in particular in the situation where multiple KMS Core nodes are running on separate physical machines.
- `core`: The KMS Core source code
    - `backup`
        - Code related to doing encrypted backups of the confidential material constructed by the threshold protocols.
    - [`grpc`](./core/grpc/README.md)
        - Protobuf files, API documentation and type conversion files (based on the protobuf) which defines the external interface of a KMS Core.
    - [`service`](./core/service/README.md)
        - The code implementing the outward-facing gRPC interface and server implementation along with PKI-related code.
    - [`threshold`](./core/threshold/README.md)
        - The code implementing the MPC protocols executing decryption, CRS and key generation, along with server code used by the MPC protocols to communicate together.
    - `util`
        - Util functions shared by the projects in `core`.
    - [`core-client`](./core-client/README.md)
        - Code for the CLI client that can be used to manually interact with the KMS Cores.
    - `docker`
        - Docker files used to containerize the different binaries in the KMS Core, e.g. the Core Service, Threshold Server and KMS Connector.
    - [`docs`](./docs/README.md)
        - High level documentation of the KMS Core system.
    - [`kms-connector`](./kms-connector/README.md)
        - The code for the KMS Connector used to interface between the KMS Core and the HTTPZ Gateway.
    - `observability`
        - Folder containing code, configurations and scripts for observability, such as through prometheus, grafana and loki.
    - `test-util`
        - Utilities used by tests in other crates within the KMS Core.


## Installation
Docker images that are ready for use can be found [here](https://github.com/zama-ai/kms-core/packages).
Ensure that you have access to the required Docker images:
  - Either use [this link](https://github.com/settings/tokens) or go to your GitHub, click you profile picture, select "Settings". Then navigate to "Developer Settings" > "Personal Access Tokens" > "Tokens (classic)" > "Generate new token (classic)". The token should have the "read:packages" permission. Afterwards, do `docker login ghcr.io` and use your github ID and the token to login. Note that this token is saved by docker locally in the clear, so it's best to only give it the permissions you need and set the expiration time to a short period of time.

## Getting started
The project requires [Docker](https://docs.docker.com/engine/install/) to be installed and running, along with [Rust](https://www.rust-lang.org/tools/install) with version >= 1.85, and the [protobuf compiler, `protoc`](https://protobuf.dev/installation/).
Ensure that these are installed on your system.

The project can be build with:
```bash
cargo build
```

Typical testing can be done using
```bash
cargo test
```
Some integration tests may require the use of additional tools. In particular some tests require Redis to be running on the local system. Further details can be found in the READMEs in each sub project. To avoid them and only run unit tests, run the following command instead:
```bash
cargo test --lib
```

To run the full test-suite (which may take several hours) run the tests with the `slow_tests` feature:
```bash
cargo test -F slow_tests
```

### High level information
For more high-level information about using and deploying the code, check out [this](./docs/README.md) section.

### Development Environment

Read this [section](./config/dev/README.md) for more information.

### Release

Read this [section](./docs/ci/release.md) for more information.


## External Resources

### Theoretical Background
- [Noah's Ark: Efficient Threshold-FHE Using Noise Flooding](https://eprint.iacr.org/2023/815)
<!--
- TODO: NIST main submission document, once it's public.
-->

### Technical specification
- [Tech spec](https://github.com/zama-ai/tech-spec/tree/main/architecture)

### HTTPZ Application Whitepaper
- [HTTPZ Whitepaper](https://github.com/zama-ai/httpz-whitepaper)

### Docker images and high level usage
- [HTTPZ Integration](https://github.com/zama-ai/httpz-test-suite)

## Working with the KMS

### Disclaimers

#### Audits
The Zama KMS has not yet been audited and should be considered in the alpha stage. Known bugs and security issues are present as reflected by issue tracking.
However, it is currently in the process of being audited.

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
  year={2025},
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
