# Trust model of the KMS core

This page states which inputs a KMS core trusts and which inputs it verifies. Read it before you review the code for security issues, and before you report a vulnerability. Many reports that describe "unauthenticated" or "unsanitized" access to the KMS core describe the intended design and are not vulnerabilities.

## Two communication interfaces

A KMS core listens on two separate gRPC interfaces. They have different peers and different trust assumptions.

1. **Core-to-core interface.** A peer-to-peer network between the KMS cores of one threshold deployment. It carries the messages of the MPC protocols. It is configured in the `[threshold]` section of the server config (`listen_address`, `listen_port`, default port 50001) and implemented in the [threshold-networking](../../core/threshold-networking/) crate. The [network protocol page](network_doc.md) describes it in detail.
2. **Service interface.** The `CoreServiceEndpoint` gRPC service defined in [kms-service.v1.proto](../../core/grpc/proto/kms-service.v1.proto). The [KMS connector](https://github.com/zama-ai/fhevm/tree/main/kms-connector) calls it to start an operation (key generation, decryption, CRS generation, epoch and context management) and to fetch the result. It is configured in the `[service]` section (`listen_address`, `listen_port`, default port 50100). The service interface works like an orchestrator channel: the connector says which operation to run, and the cores then run the MPC protocol among themselves over the core-to-core interface.

## Core-to-core interface: authenticated peers

The core-to-core interface is reachable by other KMS cores, which other operators run. The KMS core therefore authenticates every peer.

- **Mutual TLS.** Every party holds its own TLS certificate. The peer list and every MPC context carry the certificates of all parties, and these certificates form the trust store of a node. A connection that presents a certificate outside this set fails the TLS handshake. The node accepts messages only from the allowlisted set of peers.
- **Sender binding.** Every MPC message names its sender. The receiver compares this name with the Common Name of the peer certificate and rejects a mismatch with `Unauthenticated`. A peer cannot impersonate another peer.
- **Release attestation.** In an AWS Nitro Enclave deployment (`tls.auto`), the TLS certificate embeds an attestation document. The custom verifier checks the PCR0, PCR1 and PCR2 values in that document against the `trusted_releases` list, so a node only talks to a peer that runs an allowlisted release of the software. A context whose PCR allowlist is empty is rejected in an enclave deployment.
- **Insecure mode.** The `insecure` cargo feature permits plaintext transport and mock attestation. It exists for tests and local development only.

Authentication does not make a peer honest. The MPC protocol is maliciously secure: up to `t` of the `n` parties may misbehave, and the protocol still protects the secret key and produces correct results. The content of a message from an authenticated peer is therefore adversarial input, and the protocol code validates it. A bug that lets one authenticated peer break confidentiality or correctness is a real vulnerability.

## Service interface: one trusted caller

The service interface accepts every well-formed gRPC message that reaches its socket. The code has no TLS, no client authentication and no authorization for this interface, and it is not designed to sanitize or verify the intent of a request. This is by design, because the deployment restricts who can reach the socket:

- Exactly one KMS connector reaches the service interface. Deployments co-locate the connector with the core, or restrict the port with network policies and firewall rules. The [security best practices](../operations/advanced/security.md) and the [production deployment guide](../operations/production-deployment.md) describe these restrictions.
- The service interface is never reachable from the public internet.
- The same operator runs the KMS core and its KMS connector. By definition the two trust each other.

A finding that requires an attacker to send messages to the service interface therefore describes a broken deployment, not a vulnerability in the KMS core. Examples of such non-findings: "any client can call `KeyGen` or `DestroyMpcContext`", "the endpoint has no authentication", "a large request can exhaust resources", or "input from the connector is not sanitized".

The core still validates the shape of a request. It rejects a malformed request ID, unknown parameters or an inconsistent request with `InvalidArgument`. These checks protect against bugs in the caller. They are not a security boundary.

## Where validation happens

Validation of a request is split over the components of the protocol stack. The KMS core relies on the earlier layers.

| Check | Where |
| --- | --- |
| A ciphertext handle is allowed for public or user decryption (ACL) | KMS connector, against the gateway ACL contract, before it forwards the request |
| A request originates from the gateway contracts | KMS connector, which only forwards events that the gateway contracts emit |
| A request ID is unique | Gateway contracts assign the IDs; a KMS core also rejects an ID it has already seen with `AlreadyExists` |
| A ciphertext is well formed | Input proofs on the gateway and the coprocessor, before a ciphertext exists on chain |
| A user decryption request is authorized by the user | KMS core, EIP-712 signature verification |
| A peer is a legitimate KMS core that runs an allowlisted release | KMS core, mutual TLS and attestation on the core-to-core interface |
| A malicious peer cannot learn the key or corrupt a result | KMS core, the MPC protocol (see [Noah's Ark](https://eprint.iacr.org/2023/815)) |
| Stored material is consistent and untampered | KMS core, boot-time storage verification |

## Scope of a security report

Issues in scope of the [security policy](../../SECURITY.md) include:

- A KMS core accepts a core-to-core connection from a certificate outside its peer set, or a peer whose PCR values are not in `trusted_releases`.
- A single authenticated peer, or up to `t` colluding peers, can learn key material or make an honest party output a wrong result.
- Key material or other secrets reach logs, public storage or the wire in plaintext.
- Incorrect cryptography, incorrect signature verification, or a deviation from the specification.
- A malicious peer can stall or crash an honest party through the core-to-core interface.

Issues out of scope:

- Anything that requires the attacker to reach the service interface.
- Missing authentication, authorization, rate limiting or input sanitization on the service interface.
- Behavior of the `insecure` cargo feature or of the local docker-compose setup.
