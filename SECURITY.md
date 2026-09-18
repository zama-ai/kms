# Security Policy

We take security seriously. If you discover a vulnerability, please follow the guidelines below to report it to us responsibly.

## Supported Versions

Currently only v0.12.0 or newer is supported.

## Scope

Read the [trust model of the KMS core](docs/explanations/trust_model.md) before you report. In short:

- The KMS core has two gRPC interfaces. The core-to-core interface talks to other KMS cores over mutual TLS, accepts only an allowlisted set of peers, and in enclave deployments also checks the PCR values of the peer release. The service interface is called by the KMS connector to start operations.
- The service interface has no authentication or authorization in the code. The deployment ensures that exactly one KMS connector, run by the same operator as the core, can reach it, and that it is never publicly reachable. Reports that require an attacker to reach the service interface are out of scope.
- ACL checks happen in the [KMS connector](https://github.com/zama-ai/fhevm/tree/main/kms-connector). Request IDs are assigned by the gateway contracts, which bind each ID to its ciphertexts. A core tracks every ID it has accepted: key generation, preprocessing, CRS generation and context management reject a known ID; decryption retries a known ID only if the earlier attempt failed, and the synchronous decryption endpoints return the result of the earlier attempt. Retrying a decryption under a known ID is by design, because the ID carries the same ciphertexts.

The threat model assumes that at most `t` of the `n` parties are malicious. An attack that needs more than `t` malicious parties is out of scope. In scope: a bypass of peer authentication, attestation or sender binding; up to `t` malicious parties breaking confidentiality or correctness; leaked secrets; incorrect cryptography; and a client-supplied value that the core processes as a parameter (a ciphertext, a user public key, an EIP-712 payload, a parameter selector) and that causes a service outage or a confidentiality break, even though it arrives through the connector.

## Reporting a Vulnerability

If you find a security-related bug in this project, we kindly ask you to responsibly disclose it and give us
appropriate time to react, analyze and develop a fix to mitigate the found security vulnerability.

Please report any vulnerability privately using the [GitHub security advisory report](https://github.com/zama-ai/kms/security/advisories/new).

A report must point to the code it describes. Name the commit hash or the release tag of this repository that you analyzed, and give the file path and line numbers of every code location the finding relies on, for example `core/service/src/util/meta_store.rs:1019-1030` at `v0.15.0`. A report without these pointers cannot be verified and will be sent back for completion before triage.

## Recognition

We appreciate and acknowledge responsible reporters publicly (unless requested otherwise) in our security advisories and contributors list.
