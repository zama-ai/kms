// The Solana user-decryption linker's normative vectors, run through the WASM boundary.
//
// The set this suite loads — core/grpc/test-vectors/solana_linker_v1.json — is the same committed
// file the KMS Core Rust runner (core/grpc/tests/solana_linker_vectors.rs) checks itself against.
// It is read from that path, not copied here: one byte-identical source, two consumers. A record
// carries its inputs as typed fields (recipient, chain id, verifying program id, KMS context and
// epoch, handles, transport key) and, where one exists, the 32-byte `link` those fields must
// produce. Recomputing the link from the fields is the whole test; agreeing with a copy of the
// digest would not be.
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
const VECTOR_PATH = path.join(VECTOR_DIR, 'solana_linker_v1.json');
const DIGEST_PATH = path.join(VECTOR_DIR, 'solana_linker_v1.sha256');

const VECTOR_BYTES = fs.readFileSync(VECTOR_PATH);
const vectors = JSON.parse(VECTOR_BYTES.toString('utf8'));
const recordsByName = new Map(vectors.records.map((record) => [record.name, record]));

// The length of a link, in bytes and in the hex the records publish it as.
const LINK_LEN = 32;

function recordsOf(...classes) {
    return vectors.records.filter((record) => classes.includes(record.class));
}

// Transport keys are held in a table rather than inline: one of them is 1600 hex characters.
function transportKey(record) {
    const hex = vectors.transport_keys[record.transport_key];
    assert.ok(hex, `record ${record.name} names an unknown transport key ${record.transport_key}`);
    return hexToBytes(hex);
}

// The link this build computes for a record's fields. The export always computes the v1
// construction, so this is the v1 link for these fields whatever tag the record itself was written
// under. `declaredChainId` overrides the id the record's handles embed; a record's own
// `chain_id_decimal` is used when it is omitted.
function computeLink(record, declaredChainId) {
    return compute_solana_user_decrypt_link_from_js(
        hexToBytes(record.receiver_id),
        declaredChainId === undefined ? BigInt(record.chain_id_decimal) : declaredChainId,
        hexToBytes(record.verifying_program_id),
        hexToBytes(record.kms_context_id),
        hexToBytes(record.kms_epoch_id),
        record.handles,
        transportKey(record),
    );
}

// The rule name each rejecting record carries, and the message the export must fail with. Matched
// loosely — these are the stable fragments of the binding errors and of the wrapper's width guard,
// not the whole rendering.
const REJECTION_MESSAGES = {
    'empty-handle-list': /contains no ciphertext handles/,
    'handle-width': /handle at index \d+ must be 32 bytes/,
    'handle-chain-kind-bit': /does not set bit 63/,
    'mixed-embedded-chain-ids': /embeds chain ID \d+, expected \d+/,
    'declared-chain-id-mismatch': /does not match handle chain ID/,
    'identity-width': /must be 32 bytes/,
};

test('the committed vector set is the one this suite claims to load', (_t) => {
    // The cross-repository contract: every copy of this set writes the same two files, so a locally
    // adjusted or stale JSON changes the digest and fails here as well as on the Rust side.
    const digest = crypto.createHash('sha256').update(VECTOR_BYTES).digest('hex');
    const committed = fs.readFileSync(DIGEST_PATH, 'utf8').trim();

    assert.equal(committed, `${digest}  ${path.basename(VECTOR_PATH)}`);
    assert.equal(vectors.schema, 'zama-solana-linker-vectors/v1');
    assert.equal(vectors.scheme_tag, 'SolanaUserDecryptionLinker:v1');
    // A suite that reads nothing passes forever.
    assert.ok(
        vectors.records.length >= 20,
        `the set carries only ${vectors.records.length} records`,
    );
});

test('every v1 record with a link is recomputed byte for byte across the wasm boundary', (_t) => {
    // The claim the whole set exists to make: this build, reached through JS, produces exactly the
    // published link for the published fields. Divergences are included on purpose — each is a
    // valid request in its own right, and its link is as normative as the reference's.
    const linked = recordsOf('valid', 'link-divergence').filter(
        (record) => record.link && record.scheme_tag === vectors.scheme_tag,
    );
    assert.ok(linked.length >= 13, `only ${linked.length} records carried a v1 link`);

    for (const record of linked) {
        const link = computeLink(record);
        assert.equal(link.length, LINK_LEN, `${record.name} produced a ${link.length}-byte link`);
        assert.equal(bytesToHex(link), record.link, `${record.name} does not match its link`);
    }

    // Distinct records must not collapse onto one link: that is what makes each of them a test.
    const links = new Set(linked.map((record) => record.link));
    assert.equal(links.size, linked.length, 'two records share a link');
});

test('a foreign-scheme link is not the v1 link for its own fields', (_t) => {
    // Cross-version replay needs no rule of its own. A value computed under a tag this version does
    // not define simply is not the link, and byte inequality is what rejects it — no consumer parses
    // a tag out of a response to decide. The export cannot even express those tags, which is the
    // point: it computes v1, and v1 is not what these records carry.
    const foreign = recordsOf('foreign-scheme-link');
    assert.ok(foreign.length >= 2, `only ${foreign.length} foreign-scheme records`);

    for (const record of foreign) {
        assert.notEqual(record.scheme_tag, vectors.scheme_tag, `${record.name} is not foreign`);
        assert.equal(hexToBytes(record.link).length, LINK_LEN, `${record.name} is not 32 bytes`);
        assert.notEqual(
            bytesToHex(computeLink(record)),
            record.link,
            `${record.name} equals the v1 link for its own fields`,
        );
    }
});

test('every construction-reject record makes the wasm linker throw', (_t) => {
    // No link exists for these fields, so the export must refuse to produce one rather than hash
    // whatever it was handed. The rule name says which check has to fire; a negative that fails
    // "somehow" tests nothing.
    const rejects = recordsOf('construction-reject');
    assert.ok(rejects.length >= 9, `only ${rejects.length} rejecting records`);

    for (const record of rejects) {
        const expected = REJECTION_MESSAGES[record.rule];
        assert.ok(expected, `${record.name} names an unknown rule ${record.rule}`);

        // Only the declared-chain-id record is constructible: its rejection comes from the caller's
        // own chain id, which is not part of the request the constructor sees.
        const declared = record.rejected_by === 'declared-chain-id-check'
            ? BigInt(record.declared_chain_id_decimal)
            : undefined;

        assert.throws(
            () => computeLink(record, declared),
            expected,
            `${record.name} was not refused by the rule it names`,
        );
    }
});

test('every link divergence differs from the link of the record it was derived from', (_t) => {
    // Anti-substitution: each divergence changes exactly one field of an accepted base,
    // and the point of the record is that the change is visible in the link. Both the published
    // links and the ones this build recomputes must differ.
    const divergences = recordsOf('link-divergence');
    assert.ok(divergences.length >= 8, `only ${divergences.length} divergence records`);

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

test('the host chain id crosses the wasm boundary as an exact bigint', (_t) => {
    // Why the set stores chain ids as decimal *strings* and why this suite passes BigInt: a Solana
    // chain id is a u64 with bit 63 set, so it is far past the range JS numbers represent exactly.
    const lossy = vectors.records.filter(
        (record) => BigInt(record.chain_id_decimal) > BigInt(Number.MAX_SAFE_INTEGER),
    );
    assert.ok(lossy.length > 0, 'no record exercises a chain id beyond 2^53');

    for (const record of lossy) {
        const chainId = BigInt(record.chain_id_decimal);
        assert.equal(chainId >> 63n, 1n, `${record.name} does not set the chain-kind bit`);
        // Routing this id through Number would change it, silently binding a different chain.
        assert.notEqual(BigInt(Number(chainId)), chainId, `${record.name} survives a Number`);
    }

    const record = recordsByName.get('reference-two-handles');
    const chainId = BigInt(record.chain_id_decimal);
    assert.equal(bytesToHex(computeLink(record, chainId)), record.link);

    // A Number is refused at the boundary rather than rounded into a different chain id.
    assert.throws(() => computeLink(record, Number(chainId)), TypeError);

    // And the declared id is checked against the one the handles embed, so a neighbouring value is
    // not quietly hashed into a link of its own.
    assert.throws(() => computeLink(record, chainId + 1n), /does not match handle chain ID/);
});
