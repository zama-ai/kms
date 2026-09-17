# Security Policy

We take security seriously. If you discover a vulnerability, please follow the guidelines below to report it to us responsibly.

## Supported Versions

Currently only v0.12.0 or newer is supported.

## Scope

Read the [trust model of the KMS core](docs/explanations/trust_model.md) before you report. In short:

- The KMS core has two gRPC interfaces. The core-to-core interface talks to other KMS cores over mutual TLS, accepts only an allowlisted set of peers, and in enclave deployments also checks the PCR values of the peer release. The service interface is called by the KMS connector to start operations.
- The service interface has no authentication, authorization or input sanitization in the code. The deployment ensures that exactly one KMS connector, run by the same operator as the core, can reach it, and that it is never publicly reachable. Reports that require an attacker to reach the service interface are out of scope.
- ACL checks happen in the KMS connector. Request IDs are assigned by the gateway contracts, and a core rejects an ID it has already seen.

In scope: a bypass of peer authentication or attestation, a malicious peer that breaks confidentiality or correctness within the threshold bound, leaked secrets, and incorrect cryptography.

## Reporting a Vulnerability

If you find a security-related bug in this project, we kindly ask you to responsibly disclose it and give us
appropriate time to react, analyze and develop a fix to mitigate the found security vulnerability.

Please report any vulnerability privately using the [GitHub security advisory report](https://github.com/zama-ai/kms/security/advisories/new).

## Recognition

We appreciate and acknowledge responsible reporters publicly (unless requested otherwise) in our security advisories and contributors list.
