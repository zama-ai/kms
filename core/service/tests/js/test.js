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
    process_reencryption_resp_from_json,
    centralized_reencryption_request_from_transcript,
    centralized_reencryption_response_from_transcript,
    threshold_reencryption_response_from_transcript,
    u8vec_to_cryptobox_pk,
    u8vec_to_cryptobox_sk,
    new_client,
    u8vec_to_public_sig_key,
    new_eip712_domain,
    new_request_id,
    new_fhe_type,
    make_reencryption_req,
    reencryption_request_to_flat_json_string
} = require("../../pkg");

test('crypto_box', (_t) => {
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


test('crypto_box ser', (_t) => {
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

test('centralized reencryption response', (_t) => {
    // TEST_CENTRAL_WASM_TRANSCRIPT_PATH
    const transcript_buf = fs.readFileSync('temp/test-central-wasm-transcript.bin.8')
    let client = client_from_transcript(transcript_buf);

    let response = centralized_reencryption_response_from_transcript(transcript_buf);

    let pt = process_reencryption_resp(client, response.req, response.agg_resp, response.agg_resp_ids, response.enc_pk, response.enc_sk);
    assert.deepEqual(48, pt[0]);
});

test('threshold reencryption response', (_t) => {
    // TEST_THRESHOLD_WASM_TRANSCRIPT_PATH
    const transcript_buf = fs.readFileSync('temp/test-threshold-wasm-transcript.bin.8')
    let client = client_from_transcript(transcript_buf);
    let response = threshold_reencryption_response_from_transcript(transcript_buf);

    let pt = process_reencryption_resp(client, response.req, response.agg_resp, response.agg_resp_ids, response.enc_pk, response.enc_sk);
    assert.deepEqual(42, pt[0]);
});

test('new client', (_t) => {
    const public_sig_key = new Uint8Array([
        4, 33, 3, 85, 67, 103, 18, 94, 225,
        252, 7, 1, 61, 75, 2, 61, 88, 226,
        154, 45, 101, 182, 67, 207, 198, 61, 95,
        1, 208, 126, 28, 6, 15, 105, 99
    ]);
    const client_sig_key = new Uint8Array([
        4, 33, 2, 56, 109, 153, 78, 220,
        11, 175, 140, 47, 11, 165, 160, 218,
        95, 68, 4, 155, 118, 226, 161, 185,
        36, 210, 228, 244, 194, 77, 12, 90,
        88, 122, 242
    ]);
    let client = new_client([u8vec_to_public_sig_key(public_sig_key)], null, u8vec_to_public_sig_key(client_sig_key), 0, 'default');

    // create a request
    let eipmsg = new_eip712_domain("dummy", "1", new Uint8Array([1, 2, 3]), "0x010203", new Uint8Array([1, 2, 3]));
    let key_id = new_request_id("myrequestid");
    let fhe_type = new_fhe_type("euint8");
    let sig = new Uint8Array([2, 3, 4]);

    let alice_sk = cryptobox_keygen();
    let alice_pk = cryptobox_get_pk(alice_sk);

    let ct = new Uint8Array([7, 6, 5]);
    let ct_digest = new Uint8Array([7, 8, 9]);
    let req = make_reencryption_req(client, sig, alice_pk, fhe_type, key_id, ct, ct_digest, eipmsg);

    // turn the request into json
    let req_json = reencryption_request_to_flat_json_string(req);
    console.log(JSON.parse(req_json));
});

async function postData(url = "", data = "") {
    const response = await fetch(url, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
        },
        body: data,
    });
    return response.json();
}

// test('centralized integration', async (_t) => {
test('centralized integration', { skip: 'start the gateway to run integration test' }, async (_t) => {
    // DEFAULT_CENTRAL_WASM_TRANSCRIPT_PATH
    // change the .8 to something else to test with a different type
    const transcript_buf = fs.readFileSync('temp/default-central-wasm-transcript.bin.8')
    let client = client_from_transcript(transcript_buf);
    let req_struct = centralized_reencryption_request_from_transcript(client, transcript_buf, 44);
    let req_str = req_struct.inner_str;
    let req = req_struct.inner;
    let enc_pk = req_struct.enc_pk;
    let enc_sk = req_struct.enc_sk;
    let expected_pt = req_struct.pt;

    await postData("http://127.0.0.1:7077/reencrypt", req_str).then((res) => {
        console.log(res.response);
        let actual_pt = process_reencryption_resp_from_json(client, req, res.response, null, enc_pk, enc_sk);
        assert.deepEqual(expected_pt, actual_pt);
    });
});