# Solana user decryption (client path)

This guide documents the Solana user-decryption client path: what a caller must supply, which
guarantees the client enforces, what is out of scope, and how the frozen protocol bytes are
protected. If this document and the code disagree, that is a bug — file it.

## Scope

Requests travel to the KMS through the same Gateway-backed flow as EVM. Within that flow, the
client-side handling of user-decryption responses is complete and fail-closed:

- **Centralized deployments** (one KMS node) work end to end: verify, then release the plaintext.
- **Threshold deployments** work end to end as well: a multi-share response passes the full
  verification described below, and the plaintext is then reconstructed from the verified shares
  by the same recovery and Shamir-reconstruction code the EVM path runs after its own validation.
  The two paths differ only in what they validated and which receiver they open under; there is no
  Solana-only reconstruction to diverge from the EVM one.

Out of scope here, and belonging to the FHEVM integration:

- reading the selected KMS context (the trusted signer set) from on-chain Solana state — today the
  caller passes it in;
- verifying the user's Solana permit;
- proving that a response came through the expected Gateway request;
- Connector checks against Solana state;
- any transport change — the flow keeps the Gateway for now, and whether Solana later moves to
  direct Connector-to-KMS requests is an open question, not a commitment. The verification rules
  below are transport-agnostic on purpose, so the response format survives either answer.

## The linker

Every Solana user-decryption request produces one 32-byte **link**: a SHAKE256 list-hash over the
deployment pair (`verifying_program_id`, host chain id), the recipient (the raw 32-byte ed25519
wallet key), the ordered ciphertext handles, the transport key, and the request's `extra_data`
bound verbatim — the KMS never parses it, exactly as on the EVM path.
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
- **`process_user_decryption_resp_solana_from_js(client, request, solana_request, …)`** verifies
  and releases. The Solana-owned request fields travel as one named object,
  `{ user_pubkey, host_chain_id, verifying_program_id }`, with
  identities as 32-byte hex strings and `host_chain_id` as a decimal string — the vector-set
  convention, because a Solana chain id sets bit 63 and does not fit a JS number. Its trailing
  **`eip712_domain`** argument is the EIP-712 domain KMS nodes produced the response's
  `external_signature` under, in the same JS shape the EVM wrapper takes.

Both arguments are required, and both fail closed: omitting the domain leaves an empty domain
under which no real external signature verifies, and a client holding an empty signer set leaves
every share an unknown party. A caller therefore stops decrypting instead of silently accepting
response-supplied key material — this is intentional.

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
consumed by the Rust runner `core/grpc/tests/solana_linker_vectors.rs`, and
`make generate-solana-linker-vectors` regenerates it; the WASM build's agreement is pinned end to
end by
`core/service/tests/js/test.js`, whose stable transcripts fail to decrypt if the wasm-compiled
linker diverges.

The scheme tag `SolanaUserDecryptionLinker:v1`, the call separator `SOLLNK01` and the element
layout are pinned by `core/grpc/tests/solana_frozen_constants.rs`. A change to any of those bytes
is a version bump in the scheme tag, not an edit. In CI, `ci/scripts/frozen_paths.sh` fails the
build if any byte-frozen asset — the EVM references or the published Solana vectors — is modified
or deleted.

