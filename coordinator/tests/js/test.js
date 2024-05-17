const fs = require('node:fs');
const test = require('node:test');
const assert = require('node:assert').strict
const {
    cryptobox_keygen,
    cryptobox_get_pk,
    cryptobox_encrypt,
    cryptobox_decrypt,
    cryptobox_pk_to_u8vec,
    cryptobox_sk_to_u8vec,
    client_from_transcript,
    process_reencryption_resp,
    new_reenc_transcript_from_bytes,
    centralized_reencryption_response_from_transcript,
    threshold_reencryption_response_from_transcript,
    u8vec_to_cryptobox_pk,
    u8vec_to_cryptobox_sk
} = require("../../pkg");

test('crypto_box', (t) => {
    let alice_sk = cryptobox_keygen();
    let bob_sk = cryptobox_keygen();
    let alice_pk = cryptobox_get_pk(alice_sk);
    let bob_pk = cryptobox_get_pk(bob_sk);

    let pk_buf = cryptobox_pk_to_u8vec(bob_pk);
    let pk_buf_2 = cryptobox_pk_to_u8vec(alice_pk);
    assert.deepEqual(34, pk_buf.length);
    assert.notDeepEqual(pk_buf, pk_buf_2);

    const x = new Uint8Array([21, 31, 1, 2, 3]);
    let ct = cryptobox_encrypt(x, bob_pk, alice_sk);
    let pt = cryptobox_decrypt(ct, bob_sk, alice_pk);
    assert.deepEqual(x, pt);
});


test('crypto_box ser', (t) => {
    let alice_sk = cryptobox_keygen();
    let bob_sk = cryptobox_keygen();
    let alice_pk = cryptobox_get_pk(alice_sk);
    let bob_pk = cryptobox_get_pk(bob_sk);

    // we serialize and then deserialize Bob's keys
    let bob_sk_buf = cryptobox_sk_to_u8vec(bob_sk);
    let bob_pk_buf = cryptobox_pk_to_u8vec(bob_pk);
    let bob_sk_2 = u8vec_to_cryptobox_sk(bob_sk_buf);
    let bob_pk_2 = u8vec_to_cryptobox_pk(bob_pk_buf);

    const x = new Uint8Array([21, 31, 1, 2, 3]);
    let ct = cryptobox_encrypt(x, bob_pk_2, alice_sk);
    let pt = cryptobox_decrypt(ct, bob_sk_2, alice_pk);
    assert.deepEqual(x, pt);
});

test('centralized reencryption response', (t) => {
    // TEST_CENTRAL_WASM_TRANSCRIPT_PATH
    const transcript_buf = fs.readFileSync('temp/test-central-wasm-transcript.bin')
    const transcript = new_reenc_transcript_from_bytes(transcript_buf);
    let client = client_from_transcript(transcript);

    let response = centralized_reencryption_response_from_transcript(transcript);

    let pt = process_reencryption_resp(client, response.req, response.agg_resp, response.agg_resp_ids, response.enc_pk, response.enc_sk);
    assert.deepEqual(42, pt);
});

test('threshold reencryption response', (t) => {
    // TEST_THRESHOLD_WASM_TRANSCRIPT_PATH
    const transcript_buf = fs.readFileSync('temp/test-threshold-wasm-transcript.bin')
    const transcript = new_reenc_transcript_from_bytes(transcript_buf);
    let client = client_from_transcript(transcript);

    let response = threshold_reencryption_response_from_transcript(transcript);

    let pt = process_reencryption_resp(client, response.req, response.agg_resp, response.agg_resp_ids, response.enc_pk, response.enc_sk);
    assert.deepEqual(42, pt);
});
