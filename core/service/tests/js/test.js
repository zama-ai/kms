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
    public_sig_key_to_u8vec,
    get_server_public_keys,
    new_client,
    u8vec_to_public_sig_key
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
    const transcript_buf = fs.readFileSync('temp/test-central-wasm-transcript.bin.8')
    let client = client_from_transcript(transcript_buf);

    let response = centralized_reencryption_response_from_transcript(transcript_buf);

    let pt = process_reencryption_resp(client, response.req, response.agg_resp, response.agg_resp_ids, response.enc_pk, response.enc_sk);
    assert.deepEqual(48, pt[0]);
});

test('threshold reencryption response', (t) => {
    // TEST_THRESHOLD_WASM_TRANSCRIPT_PATH
    const transcript_buf = fs.readFileSync('temp/test-threshold-wasm-transcript.bin.8')
    let client = client_from_transcript(transcript_buf);
    let response = threshold_reencryption_response_from_transcript(transcript_buf);

    let pt = process_reencryption_resp(client, response.req, response.agg_resp, response.agg_resp_ids, response.enc_pk, response.enc_sk);
    assert.deepEqual(42, pt[0]);
});

test('new client', (t) => {
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
    const params = '{"ciphertext_parameters": {"lwe_dimension": 1024,"glwe_dimension": 1,"polynomial_size": 2048,"lwe_noise_distribution": {"TUniform": {"bound_log2": 41,"_phantom": null}},"glwe_noise_distribution": {"TUniform": {"bound_log2": 14,"_phantom": null}},"pbs_base_log": 21,"pbs_level": 1,"ks_base_log": 6,"ks_level": 3,"message_modulus": 4,"carry_modulus": 4,"max_noise_level": 5,"log2_p_fail": -80.0,"ciphertext_modulus": {"modulus": 0,"scalar_bits": 64},"encryption_key_choice": "Small"},"sns_parameters": {"glwe_dimension": 2,"glwe_noise_distribution": {"bound_log2": 24,"_phantom": null},"polynomial_size": 2048,"pbs_base_log": 24,"pbs_level": 3,"ciphertext_modulus": {"modulus": 0,"scalar_bits": 128}}}';
    new_client([u8vec_to_public_sig_key(public_sig_key)], [1], u8vec_to_public_sig_key(client_sig_key), 0, params);
})

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

// test('centralized integration', async (t) => {
test('centralized integration', { skip: 'start the gateway to run integration test' }, async (t) => {
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