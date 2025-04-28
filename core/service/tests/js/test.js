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
    process_user_decryption_resp,
    process_user_decryption_resp_from_js,
    u8vec_to_cryptobox_pk,
    u8vec_to_cryptobox_sk,
    new_client,
    buf_to_transcript,
    transcript_to_client,
    transcript_to_eip712domain,
    transcript_to_response,
    transcript_to_parsed_req,
    transcript_to_enc_pk,
    transcript_to_enc_sk,
    transcript_to_parsed_req_js,
    transcript_to_eip712domain_js,
    transcript_to_response_js,
} = require("../../pkg");

test('crypto_box', (_t) => {
    let alice_sk = cryptobox_keygen();
    let bob_sk = cryptobox_keygen();
    let alice_pk = cryptobox_get_pk(alice_sk);
    let bob_pk = cryptobox_get_pk(bob_sk);

    let pk_buf = cryptobox_pk_to_u8vec(bob_pk);
    let pk_buf_2 = cryptobox_pk_to_u8vec(alice_pk);
    assert.deepEqual(40, pk_buf.length);
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

test('centralized user decryption response', (_t) => {
    // TEST_CENTRAL_WASM_TRANSCRIPT_PATH
    const transcript_buf = fs.readFileSync('temp/test-central-wasm-transcript.bin.8')
    const transcript = buf_to_transcript(transcript_buf);
    const client = transcript_to_client(transcript);
    const request = transcript_to_parsed_req(transcript);
    const eip712_domain = transcript_to_eip712domain(transcript);
    const response = transcript_to_response(transcript);
    const enc_pk = transcript_to_enc_pk(transcript);
    const enc_sk = transcript_to_enc_sk(transcript);

    // test user decrypt using wasm objects
    const pt = process_user_decryption_resp(client, request, eip712_domain, response, enc_pk, enc_sk, true);
    assert.deepEqual(1, pt.length);
    assert.deepEqual(48, pt[0].bytes[0]);

    const response2 = transcript_to_response(transcript);
    const pt2 = process_user_decryption_resp(client, null, null, response2, enc_pk, enc_sk, false);
    assert.deepEqual(1, pt2.length);
    assert.deepEqual(48, pt2[0].bytes[0]);
});

test('centralized user decryption response with js', (_t) => {
    // TEST_CENTRAL_WASM_TRANSCRIPT_PATH
    const transcript_buf = fs.readFileSync('temp/test-central-wasm-transcript.bin.8')
    const transcript = buf_to_transcript(transcript_buf);
    const client = transcript_to_client(transcript);
    const request_js = transcript_to_parsed_req_js(transcript);
    const eip712_domain_js = transcript_to_eip712domain_js(transcript);
    const response_js = transcript_to_response_js(transcript);
    const enc_pk = transcript_to_enc_pk(transcript);
    const enc_sk = transcript_to_enc_sk(transcript);

    // test user decryption using js objects
    // these logs display the format of the request and response.
    console.log("centralized user decryption response")
    console.log(request_js);
    console.log(eip712_domain_js);
    console.log(response_js);
    const pt = process_user_decryption_resp_from_js(client, request_js, eip712_domain_js, response_js, enc_pk, enc_sk, true)[0].bytes;
    assert.deepEqual(48, pt.at(-1));

    const pt2 = process_user_decryption_resp_from_js(client, null, null, response_js, enc_pk, enc_sk, false)[0].bytes;
    assert.deepEqual(48, pt2.at(-1));
});

test('threshold user decryption response', (_t) => {
    // TEST_THRESHOLD_WASM_TRANSCRIPT_PATH
    const transcript_buf = fs.readFileSync('temp/test-threshold-wasm-transcript.bin.8')
    const transcript = buf_to_transcript(transcript_buf);
    const client = transcript_to_client(transcript);
    const request_js = transcript_to_parsed_req_js(transcript);
    const eip712_domain_js = transcript_to_eip712domain_js(transcript);
    const response_js = transcript_to_response_js(transcript);
    const enc_pk = transcript_to_enc_pk(transcript);
    const enc_sk = transcript_to_enc_sk(transcript);

    // test user decryption using wasm objects
    console.log("threshold user decryption response")
    console.log(request_js);
    console.log(eip712_domain_js);
    console.log(response_js);
    const pt = process_user_decryption_resp_from_js(client, request_js, eip712_domain_js, response_js, enc_pk, enc_sk, true)[0].bytes;
    assert.deepEqual(42, pt.at(-1));

    const response2_js = transcript_to_response_js(transcript);
    const pt2 = process_user_decryption_resp_from_js(client, null, null, response2_js, enc_pk, enc_sk, false)[0].bytes;
    assert.deepEqual(42, pt2.at(-1));

    // test again using fewer shares
    response_js.pop();
    const pt3 = process_user_decryption_resp_from_js(client, request_js, eip712_domain_js, response_js, enc_pk, enc_sk, true)[0].bytes;
    assert.deepEqual(42, pt3.at(-1));

    response2_js.pop();
    const pt4 = process_user_decryption_resp_from_js(client, null, null, response2_js, enc_pk, enc_sk, false)[0].bytes;
    assert.deepEqual(42, pt4.at(-1));
});

test('threshold user decryption response with js', (_t) => {
    // TEST_THRESHOLD_WASM_TRANSCRIPT_PATH
    const transcript_buf = fs.readFileSync('temp/test-threshold-wasm-transcript.bin.8')
    const transcript = buf_to_transcript(transcript_buf);
    const client = transcript_to_client(transcript);
    const request_js = transcript_to_parsed_req_js(transcript);
    const eip712_domain_js = transcript_to_eip712domain_js(transcript);
    const response_js = transcript_to_response_js(transcript);
    const enc_pk = transcript_to_enc_pk(transcript);
    const enc_sk = transcript_to_enc_sk(transcript);

    // test user decrypt using js objects
    const pt = process_user_decryption_resp_from_js(client, request_js, eip712_domain_js, response_js, enc_pk, enc_sk, true)[0].bytes;
    assert.deepEqual(42, pt.at(-1));

    const pt2 = process_user_decryption_resp_from_js(client, null, null, response_js, enc_pk, enc_sk, false)[0].bytes;
    assert.deepEqual(42, pt2.at(-1));
});

test('new client', (_t) => {
    // make a generic client
    let address = "0x66f9664f97F2b50F62D13eA064982f936dE76657";
    new_client([address], address, 'default');

    // we only need to test the constructor, no need to test is further
    // as they are handled by the other tests
});