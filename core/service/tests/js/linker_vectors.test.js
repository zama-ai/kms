// The Solana user-decryption linker's normative vectors, run through the WASM boundary.
//
// The set this suite loads — core/grpc/test-vectors/solana_linker_v2.json — is the same committed
// file the KMS Core Rust runner (core/grpc/tests/solana_linker_vectors.rs) checks itself against.
// It is read from that path, not copied here: one byte-identical source, two consumers. A record
// carries its inputs as typed fields (recipient, host chain id, verifying program id, handles,
// transport key), the Gateway domain it was hashed under and, where one exists, the 32-byte `link`
// those inputs must produce. Recomputing the link from the fields is the whole test; agreeing with
// a copy of the digest would not be.
//
// Unlike tests/js/test.js this suite needs no transcript: it depends only on the committed JSON and
// on a wasm package built with `wasm-pack build --target nodejs . --no-default-features`.

const assert = require('node:assert').strict;
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const {
    compute_solana_user_decrypt_link_from_js,
} = require("../../pkg");

// Decode a hex string (with or without a leading "0x") into a Uint8Array. Kept local so this file
// stands alone, exactly as test.js does.
function hexToBytes(hex) {
    const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
    const out = new Uint8Array(clean.length / 2);
    for (let i = 0; i < out.length; i++) {
        out[i] = parseInt(clean.substr(i * 2, 2), 16);
    }
    return out;
}

function bytesToHex(bytes) {
    return Buffer.from(bytes).toString('hex');
}

// The vectors live in the kms-grpc crate, which owns the canonical construction. Resolved from this
// file so the suite passes regardless of the cwd `node --test` is invoked from.
const VECTOR_DIR = path.join(__dirname, '..', '..', '..', 'grpc', 'test-vectors');
const VECTOR_PATH = path.join(VECTOR_DIR, 'solana_linker_v2.json');
const DIGEST_PATH = path.join(VECTOR_DIR, 'solana_linker_v2.sha256');

const VECTOR_BYTES = fs.readFileSync(VECTOR_PATH);
const vectors = JSON.parse(VECTOR_BYTES.toString('utf8'));
const recordsByName = new Map(vectors.records.map((record) => [record.name, record]));

// The length of a link, in bytes and in the hex the records publish it as.
const LINK_LEN = 32;

function recordsOf(...classes) {
    return vectors.records.filter((record) => classes.includes(record.class));
}

// Transport keys are held in a table rather than inline: one of them is 1738 hex characters.
function transportKey(record) {
    const hex = vectors.transport_keys[record.transport_key];
    assert.ok(hex, `record ${record.name} names an unknown transport key ${record.transport_key}`);
    return hexToBytes(hex);
}

// The Solana-owned request fields of a record, in the named shape both Solana WASM entry points
// take: identities as hex strings, the chain id as a decimal string. `declaredChainId` overrides
// the id the record's handles embed; the record's own `chain_id_decimal` is used when omitted.
function solanaRequestFields(record, declaredChainId) {
    return {
        user_pubkey: record.receiver_id,
        host_chain_id: declaredChainId === undefined ? record.chain_id_decimal : declaredChainId,
        verifying_program_id: record.verifying_program_id,
    };
}

// A record's Gateway domain in the JS shape the WASM entry points take — the protobuf
// `Eip712DomainMsg`: the two strings, the chain id as big-endian bytes, the EIP-55 contract
// address, no salt. The chain id crosses as bytes for the same reason the host chain id crosses as
// a decimal string: nothing here goes through a JS Number.
function domainOf(record) {
    if (record.domain === null) {
        return null;
    }
    let chainId = BigInt(record.domain.chain_id_decimal);
    const chainIdBytes = new Array(32).fill(0);
    for (let i = 31; i >= 0 && chainId > 0n; i--) {
        chainIdBytes[i] = Number(chainId & 0xffn);
        chainId >>= 8n;
    }
    return {
        name: record.domain.name,
        version: record.domain.version,
        chain_id: chainIdBytes,
        verifying_contract: record.domain.verifying_contract,
        salt: null,
    };
}

// The link this build computes for a record's fields under the record's own domain. The export
// always computes this version's construction, so this is *the* link for these inputs whatever
// construction the record itself was written under.
function computeLink(record, declaredChainId, domain) {
    return compute_solana_user_decrypt_link_from_js(
        solanaRequestFields(record, declaredChainId),
        record.handles,
        transportKey(record),
        domain === undefined ? domainOf(record) : domain,
    );
}

// The rule name each rejecting record carries, and the message the export must fail with. Matched
// loosely — these are the stable fragments of the binding errors and of the wrapper's own guards,
// not the whole rendering.
const REJECTION_MESSAGES = {
    'empty-handle-list': /contains no ciphertext handles/,
    'handle-width': /handle at index \d+ must be 32 bytes/,
    'handle-chain-type-byte': /does not have Solana type byte 0x01/,
    'mixed-embedded-chain-ids': /embeds chain ID \d+, expected \d+/,
    'declared-chain-id-mismatch': /does not match handle chain ID/,
    'identity-width': /must be 32 bytes/,
    'missing-domain': /eip712_domain is required/,
};

// Records whose link this version's export computes directly: the eip712 construction under the
// file's own type string.
function isThisVersion(record) {
    return record.construction === 'eip712' && record.type_string === vectors.type_string;
}

test('the committed vector set is the one this suite claims to load', (_t) => {
    // The cross-repository contract: every copy of this set writes the same two files, so a locally
    // adjusted or stale JSON changes the digest and fails here as well as on the Rust side.
    const digest = crypto.createHash('sha256').update(VECTOR_BYTES).digest('hex');
    const committed = fs.readFileSync(DIGEST_PATH, 'utf8').trim();

    assert.equal(committed, `${digest}  ${path.basename(VECTOR_PATH)}`);
    assert.equal(vectors.schema, 'zama-solana-linker-vectors/v2');
    assert.equal(
        vectors.type_string,
        'SolanaUserDecryptionLinker(bytes publicKey,bytes32[] handles,bytes32 userPubkey,bytes32 verifyingProgramId)',
    );
    // Node ships no keccak-256, so the type hash is pinned here as the value the Rust freeze gate
    // (core/grpc/tests/solana_frozen_constants.rs) computes and freezes.
    assert.equal(
        vectors.type_hash,
        '295b0d606d30fca99f65a509411d7fbe11187e2c4414905bea1b41b9880619dc',
    );
    // A suite that reads nothing passes forever.
    assert.ok(
        vectors.records.length >= 20,
        `the set carries only ${vectors.records.length} records`,
    );
});

test('every record with a link of this version is recomputed byte for byte across the wasm boundary', (_t) => {
    // The claim the whole set exists to make: this build, reached through JS, produces exactly the
    // published link for the published fields under the published domain. Divergences are included
    // on purpose — each is a valid request in its own right, and its link is as normative as the
    // reference's.
    const linked = recordsOf('valid', 'link-divergence').filter(
        (record) => record.link && isThisVersion(record),
    );
    assert.ok(linked.length >= 15, `only ${linked.length} records carried a link of this version`);

    for (const record of linked) {
        assert.ok(record.domain, `${record.name} has a link but no domain`);
        const link = computeLink(record);
        assert.equal(link.length, LINK_LEN, `${record.name} produced a ${link.length}-byte link`);
        assert.equal(bytesToHex(link), record.link, `${record.name} does not match its link`);
    }

    // Distinct records must not collapse onto one link: that is what makes each of them a test.
    const links = new Set(linked.map((record) => record.link));
    assert.equal(links.size, linked.length, 'two records share a link');
});

test('a foreign link is not this version\'s link for its own fields', (_t) => {
    // Cross-version replay and an undefined type need no rule of their own. A value computed under
    // a type this version does not define, or by the retired list hash, simply is not the link, and
    // byte inequality is what rejects it — no consumer parses a version out of a response to
    // decide. The export cannot even express those constructions, which is the point.
    const foreign = recordsOf('foreign-link');
    assert.ok(foreign.length >= 2, `only ${foreign.length} foreign-link records`);

    for (const record of foreign) {
        assert.ok(!isThisVersion(record), `${record.name} is not foreign`);
        assert.equal(hexToBytes(record.link).length, LINK_LEN, `${record.name} is not 32 bytes`);
        assert.notEqual(
            bytesToHex(computeLink(record)),
            record.link,
            `${record.name} equals this version's link for its own fields`,
        );
    }
});

test('every construction-reject record makes the wasm linker throw', (_t) => {
    // No link exists for these fields, so the export must refuse to produce one rather than hash
    // whatever it was handed. The rule name says which check has to fire; a negative that fails
    // "somehow" tests nothing.
    const rejects = recordsOf('construction-reject');
    assert.ok(rejects.length >= 8, `only ${rejects.length} rejecting records`);

    for (const record of rejects) {
        const expected = REJECTION_MESSAGES[record.rule];
        assert.ok(expected, `${record.name} names an unknown rule ${record.rule}`);

        // Only the declared-chain-id record is constructible: its rejection comes from the caller's
        // own chain id, which is not part of the request the constructor sees — and not part of the
        // link either, which is why that record alone carries one, equal to its base's.
        const declared = record.rejected_by === 'declared-chain-id-check'
            ? record.declared_chain_id_decimal
            : undefined;
        if (declared === undefined) {
            assert.equal(record.link, undefined, `${record.name} carries a link`);
        } else {
            assert.equal(record.link, recordsByName.get(record.derived_from).link);
        }

        assert.throws(
            () => computeLink(record, declared),
            expected,
            `${record.name} was not refused by the rule it names`,
        );
    }
});

test('a request without a domain has no link, under either spelling of absence', (_t) => {
    // The domain is a required input: `null` and `undefined` are both refused by name, and the
    // refusal comes before any field is hashed. The record pins the JSON form — `domain: null` —
    // and the export's contract covers the other JS spelling too.
    const record = recordsByName.get('missing-domain');
    assert.ok(record, 'the missing-domain record is not in the set');
    assert.equal(record.domain, null);
    assert.equal(record.rejected_by, 'domain-required');

    assert.throws(() => computeLink(record, undefined, null), /eip712_domain is required/);
    assert.throws(() => computeLink(record, undefined, undefined), /eip712_domain is required/);

    // The same fields under the reference domain are the reference link: nothing but the domain
    // was missing.
    const reference = recordsByName.get('reference-two-handles');
    assert.equal(bytesToHex(computeLink(record, undefined, domainOf(reference))), reference.link);
});

test('every link divergence differs from the link of the record it was derived from', (_t) => {
    // Anti-substitution: each divergence changes exactly one input of an accepted base, and the
    // point of the record is that the change is visible in the link. Both the published links and
    // the ones this build recomputes must differ.
    const divergences = recordsOf('link-divergence');
    assert.ok(divergences.length >= 12, `only ${divergences.length} divergence records`);

    for (const record of divergences) {
        const base = recordsByName.get(record.derived_from);
        assert.ok(base, `${record.name} names a base that is not in the set`);
        assert.ok(base.link, `${record.name} is derived from a record without a link`);

        assert.notEqual(record.link, base.link, `${record.name} shares its base's published link`);
        assert.notEqual(
            bytesToHex(computeLink(record)),
            bytesToHex(computeLink(base)),
            `${record.name} recomputes to its base's link`,
        );
    }
});

test('the Gateway domain is a link input, one field at a time', (_t) => {
    // The four domain records each move one field of the reference domain and nothing else. The
    // export must reproduce each of them, and the reference fields under the reference domain must
    // be the reference link — so it is the domain argument alone that moved the bytes.
    const reference = recordsByName.get('reference-two-handles');
    const domainRecords = vectors.records.filter((record) => record.rule === 'wrong-gateway-domain');
    assert.equal(domainRecords.length, 4, 'one record per domain field');

    for (const record of domainRecords) {
        assert.deepEqual(record.handles, reference.handles, `${record.name} moved the handles too`);
        assert.equal(bytesToHex(computeLink(record)), record.link, `${record.name} does not match`);
        // The reference fields under this record's domain are this record's link: the domain is
        // the only input that differs.
        assert.equal(
            bytesToHex(computeLink(reference, undefined, domainOf(record))),
            record.link,
            `${record.name}: the domain alone does not account for the difference`,
        );
    }
});

test('the host chain id crosses the wasm boundary as an exact decimal string', (_t) => {
    // Why the set stores chain ids as decimal *strings* and why this suite passes them through
    // unchanged: a Solana chain id is a u64 with type byte 0x01, so it is far past the range JS numbers
    // represent exactly.
    const lossy = vectors.records.filter(
        (record) => BigInt(record.chain_id_decimal) > BigInt(Number.MAX_SAFE_INTEGER),
    );
    assert.ok(lossy.length > 0, 'no record exercises a chain id beyond 2^53');

    for (const record of lossy) {
        const chainId = BigInt(record.chain_id_decimal);
        assert.equal(chainId >> 56n, 1n, `${record.name} does not have Solana type byte 0x01`);
        // Routing this id through Number would change it, silently binding a different chain.
        assert.notEqual(BigInt(Number(chainId)), chainId, `${record.name} survives a Number`);
    }

    const record = recordsByName.get('reference-two-handles');
    const chainId = BigInt(record.chain_id_decimal);
    assert.equal(bytesToHex(computeLink(record, chainId.toString())), record.link);

    // A Number is refused at the boundary rather than rounded into a different chain id.
    assert.throws(
        () => computeLink(record, Number(chainId)),
        /solana_request parsing failed/,
    );

    // And the declared id is checked against the one the handles embed, so a neighbouring value is
    // not quietly hashed into a link of its own.
    assert.throws(
        () => computeLink(record, (chainId + 1n).toString()),
        /does not match handle chain ID/,
    );
});
