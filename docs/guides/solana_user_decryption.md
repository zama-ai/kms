# Solana user decryption (client path)

This guide documents the state of the Solana user-decryption client path on the `feature/solana`
branch: what a caller must supply, which guarantees the client enforces, what is deliberately not
implemented yet, and how the frozen protocol bytes are protected. It is the rollout reference for
integrators (fhevm SDK, relayer, Connector): if this document and the code disagree, that is a
bug — file it.

## What works today, and what does not

The current proof of concept keeps the Gateway: requests travel to the KMS through the same
Gateway-backed flow as EVM. Within that flow, the client-side handling of user-decryption
responses is complete and fail-closed:

- **Centralized deployments** (one KMS node) work end to end: verify, then release the plaintext.
- **Threshold deployments** work end to end as well: a multi-share response passes the full
  verification described below, and the plaintext is then reconstructed from the verified shares
  by the same recovery and Shamir-reconstruction code the EVM path runs after its own validation.
  The two paths differ only in what they validated and which receiver they open under; there is no
  Solana-only reconstruction to diverge from the EVM one.

Out of scope for this stage, and planned for the FHEVM integration that follows:

- reading the selected KMS context (the trusted signer set) from on-chain Solana state — today the
  caller passes it in;
- verifying the user's Solana permit;
- proving that a response came through the expected Gateway request;
- Connector checks against Solana state;
- any transport change — the flow keeps the Gateway for now, and whether Solana later moves to
  direct Connector-to-KMS requests is an open question, not a commitment. The verification rules
  below are transport-agnostic on purpose, so the response format survives either answer.

## The linker, in one paragraph

Every Solana user-decryption request produces one 32-byte **link**: a SHAKE256 list-hash over the
deployment pair (`verifying_program_id`, host chain id), the recipient (the raw 32-byte ed25519
wallet key), the KMS context and epoch ids, the ordered ciphertext handles, and the transport key.
A KMS node embeds this link in its response as `payload.digest` and binds it into the
authenticated encryption of the plaintext share. The client recomputes the link from its own
request fields and accepts only responses that carry exactly that value — the response never gets
to say what the expectation is.

The transport key committed to is the complete serialized `UnifiedPublicEncKey` (869 bytes for
ML-KEM-512, produced by tfhe-rs `safe_serialization` — the same bytes the EVM permit signs).
Moving to a 32-byte key digest in permits and linkers is a possible future migration; it is not
part of v1.

## The verification contract

Response verification lives in one place, `kms_lib::client::solana_response`, and runs four rules
in fixed order:

1. **Recompute, don't parse.** The expected link is recomputed from the client's own typed request
   fields. The digest inside a response is only ever compared against it.
2. **Authenticate before comparing.** Each share's KMS node signature is verified against the
   caller-supplied trusted signer set. A share carrying a non-empty internal signature is checked
   as ECDSA over the serialized payload; an empty internal signature falls back to the EIP-712
   `external_signature`, which is fully verified (message rebuilt from the payload, the request's
   transport key and `extra_data`; recovered address compared to the registered one) — never
   merely observed to be present. A key found inside a response acts only under its binding to a
   registered address, never on its own authority.
3. **Byte equality.** The embedded digest must equal the recomputed link byte for byte.
4. **Uniformity and threshold.** Every accepted share carries the same link, each party
   contributes at most one accepted share (a replayed share is discarded, never counted twice),
   and at least the required number of distinct parties must remain — one for centralized,
   `t + 1` for a threshold deployment of `n = 3t + 1` nodes. Fewer means the response fails as a
   whole; no plaintext is released from a partially valid response.

The centralized case is the degenerate single-share case of these rules, not a weaker path of its
own.

## Calling the WASM API

The Solana entry point mirrors the EVM one: trusted configuration travels in a client object, and
the response call takes that client plus the request-side values the link commits to.

- **`new_solana_client(server_addrs, fhe_parameter)`** builds the client from trusted
  configuration: the registered KMS node signer set, as `(party id, EIP-55 address)` pairs built
  with `new_server_id_addr`, and the FHE parameter choice (`"test"` or `"default"`) a threshold
  release reconstructs under. On Solana the signer set is the host program's KMS-context signer
  set; until the on-chain lookup ships, the integrator reads it from trusted protocol
  configuration, exactly as the EVM SDK does. It is never learned from a response. Unlike
  `new_client` there is no wallet address — the recipient is the 32-byte ed25519 key passed per
  call.
- **`process_user_decryption_resp_solana_from_js(client, …)`** verifies and releases. Its trailing
  **`eip712_domain`** argument is the EIP-712 domain KMS nodes produced the response's
  `external_signature` under, in the same JS shape the EVM wrapper takes.

Both fail closed: omitting the domain leaves an empty domain under which no real external
signature verifies, and a client holding an empty signer set leaves every share an unknown party.
A caller built against the previous signature therefore stops decrypting instead of silently
accepting response-supplied key material — this is intentional. There is no migration window;
integrators must pass both.

The successful path is pinned across the wasm boundary by `core/service/tests/js/test.js`: stable
Solana vectors (one centralized, one threshold; generated deterministically by
`cargo test test_user_decryption_solana_and_write_transcript -F wasm_tests --lib`, no running KMS
needed) are driven through the public functions above, and a client configured with a foreign
signer set is asserted to reject the very same responses.

## Frozen bytes and the shared vector set

The linker v1 construction is frozen by a normative vector set:

- `core/grpc/test-vectors/solana_linker_v1.json` — accepted and rejected records, each carrying
  the typed fields, the complete byte sequence the hasher consumes, and the expected link. All
  64-bit values are decimal strings: every chain id sets bit 63, so a JSON number reaching a
  TypeScript consumer would be silently rounded.
- `core/grpc/test-vectors/solana_linker_v1.sha256` — the set's SHA-256 in `sha256sum` format.

Five implementations (SDK TypeScript, relayer, Connector Rust, KMS Core Rust, KMS client/WASM)
must consume the same bytes. Each repository holding a copy commits the same two files, and CI
compares digests: an edited copy and a stale copy are both caught. In this repository the set is
consumed twice, independently — by the Rust runner `core/grpc/tests/solana_linker_vectors.rs`
(which also regenerates the set under `ZAMA_UPDATE_SOLANA_LINKER_VECTORS=1`) and by the JS suite
`core/service/tests/js/linker_vectors.test.js` driving the WASM export.

The scheme tag `SolanaUserDecryptionLinker:v1`, the call separator `SOLLNK01` and the element
layout are pinned by `core/grpc/tests/solana_frozen_constants.rs`. From this point a change to any
of those bytes is a version bump in the scheme tag, not an edit. The EVM path is protected in the
other direction: `ci/scripts/evm_frozen_paths.sh` fails the build if byte-frozen EVM paths change
without an explicit override.

## Rollout order

1. **Now (this branch):** Solana user decryption — centralized and threshold — is safe to use
   behind the Gateway, with the caller supplying the signer set and response domain.
2. **Then (FHEVM integration):** the signer set read from the on-chain KMS context instead of
   configuration, permit verification, Connector checks, and — separately — any transport changes.
   The response format and verification rules above are designed to survive that step unchanged.
