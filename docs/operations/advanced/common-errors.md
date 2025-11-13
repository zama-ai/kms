# Common KMS Errors & Solutions

**Comprehensive error database with immediate solutions for KMS operational and development issues.**

> **Source**: This documentation consolidates and reflects real-world errors from the [Zama Notion: Encountered Issues](https://www.notion.so/zamaai/Encountered-issues-1002797be84a470ea093930bc6c971a1) document.
> **Synchronization**: This file should be kept in sync with new issues discovered and documented in the Notion database. Just export the Notion page as markdown and replace the content of this file.

# Encountered issues

A non-exhaustive list of issues that can be faced when using/developing the KMS blockchain

## [Debug end-to-end tests](https://www.notion.so/Debug-end-to-end-tests-1295a7358d5e808c8e50ea3bb756e669?pvs=21)

## Frequent errors and how to fix them

```jsx
error: unexpected argument '--pub-url' found  
```

Or

```jsx
error: unexpected argument '--priv-url' found  
```

You are using an old version and should use `--pub-path` or `--priv-path` instead , respectively.

---

```jsx
SetGlobalDefaultError("a global default trace dispatcher has already been set")
```

This typically occurs if you are setting a tracer multiple times. Implicitly this happens using `#[tracing_test::traced_test]` or through `tracing::subscriber::set_global_default` 

---

```jsx
No PRSS setup exists
```

The threshold servers have not executed the `init` step to ensure that preprocessed material is there. This should be done automatically by the CI during the launching process, but can also be done manually from the CI https://github.com/zama-ai/kms-core/blob/main/core/service/src/bin/kms-init.rs. However, be aware that this must be done for all parties at the same time.  E.g like a command like this 

```jsx
kms-init --addresses http://kms-threshold-1-threshold-core_kms-threshold_svc_50100.mesh:80 http://kms-threshold-2-threshold-core_kms-threshold_svc_50100.mesh:80 http://kms-threshold-3-threshold-core_kms-threshold_svc_50100.mesh:80 http://kms-threshold-4-threshold-core_kms-threshold_svc_50100.mesh:80
```

---

```jsx
WARN kms_lib::threshold::threshold_kms: failed to read PRSS from file with error: No such file or directory (os error 2)
INFO kms_lib::threshold::threshold_kms: Initializing threshold KMS server without PRSS Setup, remember to call the init GRPC endpoint
```

The PRSS Setup file should be stored under `keys/PRIV-pX/PrssSetup/000..0001` in `PRIV-pX`  (where `pX` refers to the parties `p1`, `p2`, etc.) and is not located there or is corrupted.

---

```jsx
2024-12-12T01:06:15.064372Z ERROR distributed_decryption::networking::grpc: msg="unknown session id SessionId(44080023662513787892309259147087
241115) for from sender Identity(\"kms-threshold-3-threshold-core:50001\") (round 1)"                                                         
2024-12-12T01:06:15.065783Z ERROR distributed_decryption::networking::grpc: msg="unknown session id SessionId(44080023662513787892309259147087
241115) for from sender Identity(\"kms-threshold-2-threshold-core:50001\") (round 1)"                                                         
2024-12-12T01:06:15.452221Z ERROR distributed_decryption::networking::grpc: msg="unknown session id SessionId(44080023662513787892309259147087
241115) for from sender Identity(\"kms-threshold-2-threshold-core:50001\") (round 1)"                                                         
2024-12-12T01:06:15.570908Z ERROR distributed_decryption::networking::grpc: msg="unknown session id SessionId(44080023662513787892309259147087
241115) for from sender Identity(\"kms-threshold-3-threshold-core:50001\") (round 1)"                                                         
2024-12-12T01:06:16.055237Z ERROR distributed_decryption::networking::grpc: msg="unknown session id SessionId(44080023662513787892309259147087
241115) for from sender Identity(\"kms-threshold-2-threshold-core:50001\") (round 1)"                                                         
2024-12-12T01:10:39.102007Z ERROR grpc_request{endpoint="/kms.CoreServiceEndpoint/GetDecryptResult" trace_id=a61cf5b10cc568f7cc38683d000b80fea
5fef7c3 request_id=a61cf5b10cc568f7cc38683d000b80fea5fef7c3 trace_id="521986241ce54ddc3e07d286876388d8"}: tower_http::trace::on_failure: respo
nse failed classification=Code: 14 latency=0 ms 
```

This "unknown session id" can happen if one party is a bit late (or the other party is too early, depends on your PoV) in theory however this should trigger a retry on the sender's party to let some time for the late party to catchup.

If one party is very late however, and does not catchup before the 3 other parties finish running the protocol, then this late party will never be able to catchup for this specific request.

---

Persistent errors in the wasm compilation and tests. E.g. this:

```jsx
error[E0432]: unresolved import `crate::sys::IoSourceState`
```

This is likely due to a missing `#[cfg(feature = "non-wasm")]` for code that is imported by the wasm code in `core/service/src/client.rs` .

---

## TFHE-rs version mismatch

Happened once when the centralized version and the threshold deployed versions didn’t use the same TFHE-rs version.
In this case one has to be extra-careful otherwise trying to load the public key might crash.

The error can look something like (but depends on the specific version/file type):

```bash
called `Result::unwrap()` on an `Err` value: reading failed on url file:///Users/dd/git/kms-core/blockchain/connector/keys/CLIENT/SigningKey/fe2f1a79515d96c5799df3f6fe6d848a4477d555: invalid value: integer `32`, expected variant index 0 <= i < 1
```

When running tests, a workaround can be to delete the `keys` directories in `core/service` and `blockchain/connector` (or whatever component is failing).

## Wrong arguments / Contract version mismatch

Happened once that the contract deployed did not match what was on main. If the expected inputs of the contract changed this will crash. To investigate this shell into the KMS validator pod and check the date of deployment of the contract. (using commands from [Useful KMS-related commands](https://www.notion.so/Useful-KMS-related-commands-bcc4fc7d55814c3baf9a2a40d8bd5e02?pvs=21)). This could also happen if the debug mode isn’t properly activated to skip the proof verification for example.

## Result of decryption is incorrect

Happened once because the public key being used was not the proper pair of the private key being deployed. Do not rely on the name of the key to make sure that you have a proper pair.
In this case copy the public key from the adequate place (S3 bucket, Docker container, Kubernetes pod …)

## Not sufficient funds

Happened that the wallet used for testing ran out of funds. One can check the different wallet funds with the script from [Useful KMS-related commands](https://www.notion.so/Useful-KMS-related-commands-bcc4fc7d55814c3baf9a2a40d8bd5e02?pvs=21). Three solutions:

- Call the faucet using the command in [Useful KMS-related commands](https://www.notion.so/Useful-KMS-related-commands-bcc4fc7d55814c3baf9a2a40d8bd5e02?pvs=21)
- Directly transfer funds from the validator or another wallet to the testing wallet using [Useful KMS-related commands](https://www.notion.so/Useful-KMS-related-commands-bcc4fc7d55814c3baf9a2a40d8bd5e02?pvs=21)
- Change testing wallets to one with more funds

## Ports errors

Can happen to anyone if not careful enough. This is just a simple reminder to always make sure that the proper ports are exposed to your [localhost](http://localhost) when using the kubernetes cluster or the docker containers. Some confusion can happen from similar services (similar name and basically same function) from the FHEVM and the KMS using similar but different ports.

## Wallet not found

This can happen if the bootstrapping of the blockchain encountered a bug, was never done or the documentation/configurations run out of date/sync with what is deployed. To investigate this shell into the validator and list the wallets. You can also take a look at the logs resulting from the bootstrapping script, taking a look at the script itself inside the pod/contrainer can also help.

## Integration test failures in the gateway/simulator

You probably have not build all the needed docker images or have old images present in docker. Try to delete the current docker images and rebuild. See blockchain/simulator/README.md for details of the prerequisite and docker commands.

## Install errors

- `The system library openssl required by crate openssl-sys was not found.`
    
    Solution:    `sudo apt-get install libssl-dev`
    

## Too many files error

The error `"Too many open files”` on a Mac has an easy fix. Adding the `ulimit -n 1024` statement to your bash profile using **sudo nano .bash_profile** handles it. 

## Failing blockchain connector integration test

Encountering the following error can have different causes.

```bash
---- test_blockchain_connector stdout ----
thread 'test_blockchain_connector' panicked at blockchain/connector/tests/integration_test.rs:103:70:
called `Result::unwrap()` on an `Err` value: Contract not found
```

The actual error should be visible on the kms full node, which can be seen by investigating the docker logs.

- Example kms full node log, showing errors
    
    `2024-09-02 10:22:16 kms-full-node-1  | 8:22AM ERR failure when running app err="rpc error: code = Unknown desc = 
    github.com/cosmos/cosmos-sdk/baseapp.gRPCErrorToSDKError
    	github.com/cosmos/cosmos-sdk@v0.50.6/baseapp/abci.go:1169
    github.com/cosmos/cosmos-sdk/baseapp.(*BaseApp).handleQueryGRPC
    	github.com/cosmos/cosmos-sdk@v0.50.6/baseapp/abci.go:1141
    github.com/cosmos/cosmos-sdk/baseapp.(*BaseApp).Query
    	github.com/cosmos/cosmos-sdk@v0.50.6/baseapp/abci.go:177
    github.com/cosmos/cosmos-sdk/server.cometABCIWrapper.Query
    	github.com/cosmos/cosmos-sdk@v0.50.6/server/cmt_abci.go:24
    github.com/cometbft/cometbft/abci/client.(*localClient).Query
    	github.com/cometbft/cometbft@v0.38.6/abci/client/local_client.go:106
    github.com/cometbft/cometbft/proxy.(*appConnQuery).Query
    	github.com/cometbft/cometbft@v0.38.6/proxy/app_conn.go:181
    github.com/cometbft/cometbft/rpc/core.(*Environment).ABCIQuery
    	github.com/cometbft/cometbft@v0.38.6/rpc/core/abci.go:22
    reflect.Value.call
    	reflect/value.go:596
    reflect.Value.Call
    	reflect/value.go:380
    github.com/cometbft/cometbft/rpc/jsonrpc/server.RegisterRPCFuncs.makeJSONRPCHandler.func3
    	github.com/cometbft/cometbft@v0.38.6/rpc/jsonrpc/server/http_json_handler.go:108
    github.com/cometbft/cometbft/rpc/jsonrpc/server.RegisterRPCFuncs.handleInvalidJSONRPCPaths.func4
    	github.com/cometbft/cometbft@v0.38.6/rpc/jsonrpc/server/http_json_handler.go:140
    net/http.HandlerFunc.ServeHTTP
    	net/http/server.go:2136
    net/http.(*ServeMux).ServeHTTP
    	net/http/server.go:2514
    github.com/cometbft/cometbft/node.(*Node).startRPC.(*Cors).Handler.func9
    	github.com/rs/cors@v1.8.3/cors.go:236
    net/http.HandlerFunc.ServeHTTP
    	net/http/server.go:2136
    github.com/cometbft/cometbft/rpc/jsonrpc/server.maxBytesHandler.ServeHTTP
    	github.com/cometbft/cometbft@v0.38.6/rpc/jsonrpc/server/http_server.go:256
    github.com/cometbft/cometbft/rpc/jsonrpc/server.Serve.RecoverAndLogHandler.func1
    	github.com/cometbft/cometbft@v0.38.6/rpc/jsonrpc/server/http_server.go:229
    net/http.HandlerFunc.ServeHTTP
    	net/http/server.go:2136
    net/http.serverHandler.ServeHTTP
    	net/http/server.go:2938
    net/http.(*conn).serve
    	net/http/server.go:2009
    rpc error: code = Unknown desc = failed to execute message; message index: 0: uncompress wasm archive: max 819200 bytes: exceeds limit: create wasm contract failed [cosmossdk.io/errors@v1.0.1/errors.go:151] with gas used: '2937699': unknown request"
    
    2024-09-02 10:22:17 kms-full-node-1  | 8:22AM ERR failure when running app err="rpc error: code = Unknown desc = 
    github.com/cosmos/cosmos-sdk/baseapp.gRPCErrorToSDKError
    	github.com/cosmos/cosmos-sdk@v0.50.6/baseapp/abci.go:1169
    github.com/cosmos/cosmos-sdk/baseapp.(*BaseApp).handleQueryGRPC
    	github.com/cosmos/cosmos-sdk@v0.50.6/baseapp/abci.go:1141
    github.com/cosmos/cosmos-sdk/baseapp.(*BaseApp).Query
    	github.com/cosmos/cosmos-sdk@v0.50.6/baseapp/abci.go:177
    github.com/cosmos/cosmos-sdk/server.cometABCIWrapper.Query
    	github.com/cosmos/cosmos-sdk@v0.50.6/server/cmt_abci.go:24
    github.com/cometbft/cometbft/abci/client.(*localClient).Query
    	github.com/cometbft/cometbft@v0.38.6/abci/client/local_client.go:106
    github.com/cometbft/cometbft/proxy.(*appConnQuery).Query
    	github.com/cometbft/cometbft@v0.38.6/proxy/app_conn.go:181
    github.com/cometbft/cometbft/rpc/core.(*Environment).ABCIQuery
    	github.com/cometbft/cometbft@v0.38.6/rpc/core/abci.go:22
    reflect.Value.call
    	reflect/value.go:596
    reflect.Value.Call
    	reflect/value.go:380
    github.com/cometbft/cometbft/rpc/jsonrpc/server.RegisterRPCFuncs.makeJSONRPCHandler.func3
    	github.com/cometbft/cometbft@v0.38.6/rpc/jsonrpc/server/http_json_handler.go:108
    github.com/cometbft/cometbft/rpc/jsonrpc/server.RegisterRPCFuncs.handleInvalidJSONRPCPaths.func4
    	github.com/cometbft/cometbft@v0.38.6/rpc/jsonrpc/server/http_json_handler.go:140
    net/http.HandlerFunc.ServeHTTP
    	net/http/server.go:2136
    net/http.(*ServeMux).ServeHTTP
    	net/http/server.go:2514
    github.com/cometbft/cometbft/node.(*Node).startRPC.(*Cors).Handler.func9
    	github.com/rs/cors@v1.8.3/cors.go:236
    net/http.HandlerFunc.ServeHTTP
    	net/http/server.go:2136
    github.com/cometbft/cometbft/rpc/jsonrpc/server.maxBytesHandler.ServeHTTP
    	github.com/cometbft/cometbft@v0.38.6/rpc/jsonrpc/server/http_server.go:256
    github.com/cometbft/cometbft/rpc/jsonrpc/server.Serve.RecoverAndLogHandler.func1
    	github.com/cometbft/cometbft@v0.38.6/rpc/jsonrpc/server/http_server.go:229
    net/http.HandlerFunc.ServeHTTP
    	net/http/server.go:2136
    net/http.serverHandler.ServeHTTP
    	net/http/server.go:2938
    net/http.(*conn).serve
    	net/http/server.go:2009
    rpc error: code = Unknown desc = failed to execute message; message index: 0: Error calling the VM: Error during static Wasm validation: Wasm contract requires unsupported import: \"__wbindgen_placeholder__.__wbindgen_describe\". Required imports: {\"__wbindgen_externref_xform__.__wbindgen_externref_table_grow\", \"__wbindgen_externref_xform__.__wbindgen_externref_table_set_null\", \"__wbindgen_placeholder__.__wbindgen_describe\", ... 1 more}. Available imports: [\"env.abort\", \"env.db_read\", \"env.db_write\", \"env.db_remove\", \"env.addr_validate\", \"env.addr_canonicalize\", \"env.addr_humanize\", \"env.secp256k1_verify\", \"env.secp256k1_recover_pubkey\", \"env.ed25519_verify\", \"env.ed25519_batch_verify\", \"env.debug\", \"env.query_chain\", \"env.db_scan\", \"env.db_next\", \"env.db_next_key\", \"env.db_next_value\"].: create wasm contract failed [CosmWasm/wasmd/x/wasm/keeper/keeper.go:175] with gas used: '1861243': unknown request"`
    

The above errors were likely caused by using the `getrandom` package with the `js` feature in the `tendermint` and `asc` contracts `Cargo.toml`. This however was required, since we wanted to use `ethers::U256` in the connector. The reason is probably incomplete `wasm` support of some of these features.

Another error occurred was us exceeding some **smart contract size limit** with the ASC after adding too many values to the `OperationValues` being processed in another case.

The error looked like this:

- Error log showing exceeded size during ASC deployment
    
    ```
    ERR failure when running app err="rpc error: code = Unknown desc =
    [github.com/cosmos/cosmos-sdk/baseapp.gRPCErrorToSDKError](http://github.com/cosmos/cosmos-sdk/baseapp.gRPCErrorToSDKError)[github.com/cosmos/cosmos-sdk@v0.50.6/baseapp/abci.go:1169](http://github.com/cosmos/cosmos-sdk@v0.50.6/baseapp/abci.go:1169)[github.com/cosmos/cosmos-sdk/baseapp.(*BaseApp](http://github.com/cosmos/cosmos-sdk/baseapp.(*BaseApp)).handleQueryGRPC
    [github.com/cosmos/cosmos-sdk@v0.50.6/baseapp/abci.go:1141](http://github.com/cosmos/cosmos-sdk@v0.50.6/baseapp/abci.go:1141)[github.com/cosmos/cosmos-sdk/baseapp.(*BaseApp](http://github.com/cosmos/cosmos-sdk/baseapp.(*BaseApp)).Query
    [github.com/cosmos/cosmos-sdk@v0.50.6/baseapp/abci.go:177](http://github.com/cosmos/cosmos-sdk@v0.50.6/baseapp/abci.go:177)[github.com/cosmos/cosmos-sdk/server.cometABCIWrapper.Query](http://github.com/cosmos/cosmos-sdk/server.cometABCIWrapper.Query)[github.com/cosmos/cosmos-sdk@v0.50.6/server/cmt_abci.go:24](http://github.com/cosmos/cosmos-sdk@v0.50.6/server/cmt_abci.go:24)[github.com/cometbft/cometbft/abci/client.(*localClient](http://github.com/cometbft/cometbft/abci/client.(*localClient)).Query
    [github.com/cometbft/cometbft@v0.38.6/abci/client/local_client.go:106](http://github.com/cometbft/cometbft@v0.38.6/abci/client/local_client.go:106)[github.com/cometbft/cometbft/proxy.(*appConnQuery](http://github.com/cometbft/cometbft/proxy.(*appConnQuery)).Query
    [github.com/cometbft/cometbft@v0.38.6/proxy/app_conn.go:181](http://github.com/cometbft/cometbft@v0.38.6/proxy/app_conn.go:181)[github.com/cometbft/cometbft/rpc/core.(*Environment](http://github.com/cometbft/cometbft/rpc/core.(*Environment)).ABCIQuery
    [github.com/cometbft/cometbft@v0.38.6/rpc/core/abci.go:22](http://github.com/cometbft/cometbft@v0.38.6/rpc/core/abci.go:22)
    reflect.Value.call
    reflect/value.go:596
    reflect.Value.Call
    reflect/value.go:380
    [github.com/cometbft/cometbft/rpc/jsonrpc/server.RegisterRPCFuncs.makeJSONRPCHandler.func3](http://github.com/cometbft/cometbft/rpc/jsonrpc/server.RegisterRPCFuncs.makeJSONRPCHandler.func3)[github.com/cometbft/cometbft@v0.38.6/rpc/jsonrpc/server/http_json_handler.go:108](http://github.com/cometbft/cometbft@v0.38.6/rpc/jsonrpc/server/http_json_handler.go:108)[github.com/cometbft/cometbft/rpc/jsonrpc/server.RegisterRPCFuncs.handleInvalidJSONRPCPaths.func4](http://github.com/cometbft/cometbft/rpc/jsonrpc/server.RegisterRPCFuncs.handleInvalidJSONRPCPaths.func4)[github.com/cometbft/cometbft@v0.38.6/rpc/jsonrpc/server/http_json_handler.go:140](http://github.com/cometbft/cometbft@v0.38.6/rpc/jsonrpc/server/http_json_handler.go:140)
    net/http.HandlerFunc.ServeHTTP
    net/http/server.go:2136
    net/http.(*ServeMux).ServeHTTP
    net/http/server.go:2514
    [github.com/cometbft/cometbft/node.(*Node](http://github.com/cometbft/cometbft/node.(*Node)).startRPC.(*Cors).Handler.func9
    [github.com/rs/cors@v1.8.3/cors.go:236](http://github.com/rs/cors@v1.8.3/cors.go:236)
    net/http.HandlerFunc.ServeHTTP
    net/http/server.go:2136
    [github.com/cometbft/cometbft/rpc/jsonrpc/server.maxBytesHandler.ServeHTTP](http://github.com/cometbft/cometbft/rpc/jsonrpc/server.maxBytesHandler.ServeHTTP)[github.com/cometbft/cometbft@v0.38.6/rpc/jsonrpc/server/http_server.go:256](http://github.com/cometbft/cometbft@v0.38.6/rpc/jsonrpc/server/http_server.go:256)[github.com/cometbft/cometbft/rpc/jsonrpc/server.Serve.RecoverAndLogHandler.func1](http://github.com/cometbft/cometbft/rpc/jsonrpc/server.Serve.RecoverAndLogHandler.func1)[github.com/cometbft/cometbft@v0.38.6/rpc/jsonrpc/server/http_server.go:229](http://github.com/cometbft/cometbft@v0.38.6/rpc/jsonrpc/server/http_server.go:229)
    net/http.HandlerFunc.ServeHTTP
    net/http/server.go:2136
    net/http.serverHandler.ServeHTTP
    net/http/server.go:2938
    net/http.(*conn).serve
    net/http/server.go:2009
    rpc error: code = Unknown desc = failed to execute message; message index: 0: uncompress wasm archive: max 819200 bytes: exceeds limit: create wasm contract failed [[cosmossdk.io/errors@v1.0.1/errors.go:151](http://cosmossdk.io/errors@v1.0.1/errors.go:151)] with gas used: '2678783': unknown request"
    ```
    

A workaround was to go from normal size optimization to aggressive size optimization using `wasm-opt`, i.e. changing `-Os` to `-Oz` in the `dev.dockerfile` that builds and optimizes the ASC. Alternative optimizers like [cosmwasm optimizer](https://github.com/CosmWasm/optimizer) might be another idea. We might also need a more generic solution in the future that reduces code size by design. Maybe splitting up the ASC into multiple contracts. More details here: https://github.com/zama-ai/kms-core/issues/1230.

## Blockchain time out when getting response

This is probably an issue with the docker images. Delete the old ones and build them again using 

```rust
docker compose -vvv -f docker-compose-kms-base.yml -f docker-compose-kms-threshold.yml build
docker compose -vvv -f docker-compose-kms-base.yml -f docker-compose-kms-centralized.yml build
```

## Missing field in ASC

If there's an `missing field <field name>` issue in ASC, for example when running the simulator tests. Check that the field parameter in the contract function matches the `serde(rename(...))` proc macro in `blockchain/events/src/kms.rs` . For example, the function below has the field `verify_proven_ct`. 

```rust
    #[sv::msg(exec)]
    pub fn verify_proven_ct(
        &self,
        ctx: ExecCtx,
        verify_proven_ct: VerifyProvenCtValues,
    ) -> StdResult<Response> {
        let txn_id = self.derive_transaction_id(&ctx.env)?;
        self.process_transaction(ctx.deps.storage, &ctx.env, &txn_id, verify_proven_ct)
    }
```

It must match the proc macro above the enum variant.

```rust
#[versionize(OperationValueVersioned)]
pub enum OperationValue {
    #[strum(serialize = "verify_proven_ct")]
    #[serde(rename = "verify_proven_ct")]
    VerifyProvenCt(VerifyProvenCtValues),

}
```

## Transactions not posted to the ASC.

You may see an error like the following:

```jsx
2024-10-11T13:18:52.460274Z  INFO integration_test: Getting contract address....
2024-10-11T13:18:52.465500Z  INFO integration_test: Transaction: Ok(TxResponse { height: 0, txhash: "82C6A5F04377E3B31F72A3111E2B629AB193D04DF8B6614708614772E6CD7E06", codespace: "", code: 0, data: "", raw_log: "", logs: [], info: "", gas_wanted: 0, gas_used: 0, tx: None, timestamp: "", events: [] })
thread 'test_blockchain_connector' panicked at blockchain/connector/tests/integration_test.rs:160:10:
called `Result::unwrap()` on an `Err` value: Transaction error QueryError("Transaction found for \"82C6A5F04377E3B31F72A3111E2B629AB193D04DF8B6614708614772E6CD7E06\" with error code 5 and message \"\\ngithub.com/CosmWasm/wasmd/x/wasm/keeper.Keeper.execute\\n\\tgithub.com/CosmWasm/wasmd/x/wasm/keeper/keeper.go:422\\ngithub.com/CosmWasm/wasmd/x/wasm/keeper.msgServer.ExecuteContract\\n\\tgithub.com/CosmWasm/wasmd/x/wasm/keeper/msg_server.go:124\\ngithub.com/CosmWasm/wasmd/x/wasm/types._Msg_ExecuteContract_Handler.func1\\n\\tgithub.com/CosmWasm/wasmd/x/wasm/types/tx.pb.go:2265\\ngithub.com/cosmos/cosmos-sdk/baseapp.(*MsgServiceRouter).registerMsgServiceHandler.func2.1\\n\\tgithub.com/cosmos/cosmos-sdk@v0.50.6/baseapp/msg_service_router.go:175\\ngithub.com/CosmWasm/wasmd/x/wasm/types._Msg_ExecuteContract_Handler\\n\\tgithub.com/CosmWasm/wasmd/x/wasm/types/tx.pb.go:2267\\ngithub.com/cosmos/cosmos-sdk/baseapp.(*MsgServiceRouter).registerMsgServiceHandler.func2\\n\\tgithub.com/cosmos/cosmos-sdk@v0.50.6/baseapp/msg_service_router.go:198\\ngithub.com/cosmos/cosmos-sdk/baseapp.(*BaseApp).runMsgs\\n\\tgithub.com/cosmos/cosmos-sdk@v0.50.6/baseapp/baseapp.go:1010\\ngithub.com/cosmos/cosmos-sdk/baseapp.(*BaseApp).runTx\\n\\tgithub.com/cosmos/cosmos-sdk@v0.50.6/baseapp/baseapp.go:948\\ngithub.com/cosmos/cosmos-sdk/baseapp.(*BaseApp).deliverTx\\n\\tgithub.com/cosmos/cosmos-sdk@v0.50.6/baseapp/baseapp.go:763\\ngithub.com/cosmos/cosmos-sdk/baseapp.(*BaseApp).internalFinalizeBlock\\n\\tgithub.com/cosmos/cosmos-sdk@v0.50.6/baseapp/abci.go:790\\ngithub.com/cosmos/cosmos-sdk/baseapp.(*BaseApp).FinalizeBlock\\n\\tgithub.com/cosmos/cosmos-sdk@v0.50.6/baseapp/abci.go:884\\ngithub.com/cosmos/cosmos-sdk/server.cometABCIWrapper.FinalizeBlock\\n\\tgithub.com/cosmos/cosmos-sdk@v0.50.6/server/cmt_abci.go:44\\ngithub.com/cometbft/cometbft/abci/client.(*localClient).FinalizeBlock\\n\\tgithub.com/cometbft/cometbft@v0.38.6/abci/client/local_client.go:185\\ngithub.com/cometbft/cometbft/proxy.(*appConnConsensus).FinalizeBlock\\n\\tgithub.com/cometbft/cometbft@v0.38.6/proxy/app_conn.go:104\\ngithub.com/cometbft/cometbft/state.(*BlockExecutor).ApplyBlock\\n\\tgithub.com/cometbft/cometbft@v0.38.6/state/execution.go:213\\ngithub.com/cometbft/cometbft/consensus.(*State).finalizeCommit\\n\\tgithub.com/cometbft/cometbft@v0.38.6/consensus/state.go:1771\\ngithub.com/cometbft/cometbft/consensus.(*State).tryFinalizeCommit\\n\\tgithub.com/cometbft/cometbft@v0.38.6/consensus/state.go:1682\\ngithub.com/cometbft/cometbft/consensus.(*State).enterCommit.func1\\n\\tgithub.com/cometbft/cometbft@v0.38.6/consensus/state.go:1617\\ngithub.com/cometbft/cometbft/consensus.(*State).enterCommit\\n\\tgithub.com/cometbft/cometbft@v0.38.6/consensus/state.go:1655\\ngithub.com/cometbft/cometbft/consensus.(*State).addVote\\n\\tgithub.com/cometbft/cometbft@v0.38.6/consensus/state.go:2334\\ngithub.com/cometbft/cometbft/consensus.(*State).tryAddVote\\n\\tgithub.com/cometbft/cometbft@v0.38.6/consensus/state.go:2066\\ngithub.com/cometbft/cometbft/consensus.(*State).handleMsg\\n\\tgithub.com/cometbft/cometbft@v0.38.6/consensus/state.go:929\\ngithub.com/cometbft/cometbft/consensus.(*State).receiveRoutine\\n\\tgithub.com/cometbft/cometbft@v0.38.6/consensus/state.go:856\\nfailed to execute message; message index: 0: Error parsing into type tendermint_ipsc::contract::sv::ContractExecMsg: Unsupported message received: {\\\"decrypt\\\":{\\\"decrypt\\\":{\\\"acl_address\\\":\\\"0xEEdA6bf26964aF9D7Eed9e03e53415D37aa960EE\\\",\\\"ciphertext_handles\\\":[\\\"00000000000101010101\\\"],\\\"eip712_chain_id\\\":\\\"6565656565656565656565656565656565656565656565656565656565656565\\\",\\\"eip712_name\\\":\\\"eip712name\\\",\\\"eip712_salt\\\":\\\"\\\",\\\"eip712_verifying_contract\\\":\\\"0x33dA6bF26964af9d7eed9e03E53415D37aA960EE\\\",\\\"eip712_version\\\":\\\"1\\\",\\\"external_handles\\\":[\\\"01000000000101010101\\\"],\\\"fhe_types\\\":[\\\"euint8\\\"],\\\"key_id\\\":\\\"010203\\\",\\\"proof\\\":\\\"some_proof\\\",\\\"version\\\":1}}}. Messages supported by this contract: verify_proof: execute wasm contract failed\"")
```

If you dive into the logs from Docker you may find the following line in the log `max 819200 bytes: exceeds limit: create wasm contract failed [[cosmossdk.io/errors@v1.0.1/errors.go:151](http://cosmossdk.io/errors@v1.0.1/errors.go:151)] with gas used: '2786840': unknown request"` 

Basically the smart contract is too big. You can try to optimize it more aggresively as suggested [here](https://github.com/zama-ai/kms-core/issues/1230) 

Otherwise something more drastic is needed…

### Tracing logs for unit tests

The following code snippet can be called for example from a unit test to see proper tracing logs.

It does the following things and can naturally be customized accordingly: 

- it shows `DEBUG` logs for `kms` (core service) and `distributed-decryption` (core engine) and restricts tonic to `INFO` logs (the debug ones are excessive).
- It writes the logs to a file (`mylog.log`).

```rust
    use tracing_appender::rolling::{RollingFileAppender, Rotation};
    use tracing_subscriber::fmt::writer::MakeWriterExt;

    pub fn setup_logging() {
        let file_appender = RollingFileAppender::new(Rotation::DAILY, "logs", "mylog.log");
        let file_and_stdout = file_appender.and(std::io::stdout);
        let subscriber = tracing_subscriber::fmt()
            .with_writer(file_and_stdout)
            .with_ansi(false)
            .with_env_filter("kms=debug,distributed-decryption=debug,tonic=info")
            .finish();
        tracing::subscriber::set_global_default(subscriber).expect("Failed to set subscriber");
    }
```

## CI: Issue with docker build on Graviton / ssh

Currently docker images are built for both `linux/amd64`  and `linux/arm64` architecture.

This is done by building on an ARM based AWS instance (using Graviton processor) and the instance was created with terraform (see https://github.com/zama-ai/kms-core/blob/main/.github/operations/terraform/environments/build/main.tf)

this Graviton host is connected through SSH (key being stored in Blockchain 1password vault).

✅ We had an issue where the host was not responding to ssh, rebooting it changed the IP and we updated it to use a fixed IP (AWS Elastic IP) https://github.com/zama-ai/kms-core/pull/1334

🚧 We have another open issue about concurrency that was certainly the root cause of our first issue, if too much PR are opened at the same time, load reaches 50 on the graviton host and ssh is no longer responding. Right now the fix was limiting the build only for main but there is certainly other way to fix it properly.

If you have an issue with this host it’s safe to reboot it and nothing has to be updated on Github side. Instance being https://eu-west-3.console.aws.amazon.com/ec2/home?region=eu-west-3#InstanceDetails:instanceId=i-0cae1d67123ea86fd

## Build local core docker images

It’s a 2 step process, since CI and DEV share the same base docker image.

```bash
docker compose -f docker-compose-kms-base.yml -f docker-compose-kms-centralized.yml build kms-core-base-build
docker compose -f docker-compose-kms-base.yml -f docker-compose-kms-centralized.yml build dev-kms-core
```

If you were using the docker files directly it would be:

```bash
docker build core/service/operations/docker/ci.dockerfile -t ghcr.io/zama-ai/kms-service:latest
docker build core/service/operations/docker/dev.dockerfile -t ghcr.io/zama-ai/kms-service-dev:latest

```

## “MODE is  which is neither 'threshold' nor 'centralized’”

in docker logs, for KMS validator service,  if you get :

```jsx
Instantiating ASCs
MODE is  which is neither 'threshold' nor 'centralized', can't instantiate smart contract
```

- in `fhevm-L1-demo`repo, modify `docker-compose/docker-compose-full.yaml`, for the `kms-validator` service, by adding the following (or `threshold`) :

```jsx
    environment:
      - MODE=centralized
```

- for more info, follow the same last steps as in [Option 2: the ASC + other stuff changed](https://www.notion.so/Option-2-the-ASC-other-stuff-changed-1295a7358d5e80c5a672d86ff223094a?pvs=21) (add a `MODE` to `kms-validator`  service)

## “transaction failed for ethereum-asc”

in docker logs, for KMS validator service,  if you get :

```jsx
Ethereum ASC contract address: transaction failed for ethereum-asc
```

instead of something like 

```jsx
Ethereum ASC contract address: wasm1nc5tatafv6eyq7llkr2gv50ff9e22mnf70qgjlv737ktmt4eswrqr5j2ht
```

then try to :

- simply re-run the kms (`make stop-kms` + `make run-kms` )
- or add more sleep at l47 in `asc/boostrap_asc.sh`  (**`fhevm-L1-demo` repo)**

## gateway does not recognize the ASC contract

then that most likely means you don’t have the right ASC contract address configured for the gateway

- in `fhevm-L1-demo`repo, in docker logs, within the kms validator service, check for `Ethereum ASC contract address:` and copy paste the address next to it: this is the new ASC address
- go back to the `kms-core` repo in `blockchain/gateway` and modify `config/gateway.toml` to update `contract_address` to this new address
- run `cargo run --bin gateway` as usual

## gateway does not connect

if you get something like :

```jsx
2024-10-24T17:52:19.813031Z  WARN gateway::common::provider: Failed to connect to WebSocket provider (attempt 1): JsonRpcClientError(InternalError(Io(Os { code: 61, kind: ConnectionRefused, message: "Connection refused" }))). Retrying in 2 seconds.
2024-10-24T17:52:21.816332Z  WARN gateway::common::provider: Failed to connect to WebSocket provider (attempt 2): JsonRpcClientError(InternalError(Io(Os { code: 61, kind: ConnectionRefused, message: "Connection refused" }))). Retrying in 4 seconds.
2024-10-24T17:52:25.819766Z  WARN gateway::common::provider: Failed to connect to WebSocket provider (attempt 3): JsonRpcClientError(InternalError(Io(Os { code: 61, kind: ConnectionRefused, message: "Connection refused" }))). Retrying in 8 seconds.
2024-10-24T17:52:33.822688Z  WARN gateway::common::provider: Failed to connect to WebSocket provider (attempt 4): JsonRpcClientError(InternalError(Io(Os { code: 61, kind: ConnectionRefused, message: "Connection refused" }))). Retrying in 16 seconds.
2024-10-24T17:52:49.825639Z  WARN gateway::common::provider: Failed to connect to WebSocket provider (attempt 5): JsonRpcClientError(InternalError(Io(Os { code: 61, kind: ConnectionRefused, message: "Connection refused" }))). Retrying in 32 seconds.
2024-10-24T17:53:21.828089Z ERROR gateway::common::provider: Max reconnection attempts reached.
```

then there’s a change that the demo does not work properly :

- check that all docker containers are running (docker desktop or `docker container ls`

## `assertion 'left == right' failed` from tfhe-rs

When getting an issue like in https://github.com/zama-ai/kms-core/issues/1422#issuecomment-2460248552 :

```jsx
thread '<unnamed>' panicked at /var/cache/buildkit/cargo/registry/src/index.crates.io-6f17d22bba15001f/tfhe-0.9.1/src/core_crypto/algorithms/lwe_programmable_bootstrapping/fft64.rs:252:5:
assertion `left == right` failed
  left: LweSize(1281)
 right: LweSize(1025)
```

- this most likely indicates a tfhe-rs version mismatch :
    - error indicates that we are using a decompression key different from the one used for compressing the input ciphertext
    - in particular, this was using keys from tfhe-rs 0.8 or prior
- solution was to use the latest generated keys from the deployed storage (check with marcus)

## `"We can't deserialize our own validated sks key"` from fhevm-backend

If you get an error like : 

```jsx
2024-11-06 18:24:35 We can't deserialize our own validated sks key: DeserializationError("invalid value: integer `1`, expected variant index 0 <= i < 1")
```

- this most likely indicates a tfhe-rs version mismatch :
    - error comes from fhevm-backend (coprocessor) when deserializing keys
    - it is triggered by tfhe-rs but the error message is not caught
- solution was to update the coprocessor image used in the l1 demo :
    - update image in `docker-compose.yaml` from `work_dir/fhevm-backend/fhevm-engine/coprocessor` from :
    
    ```jsx
      coproc:
        image: ghcr.io/zama-ai/fhevm-coprocessor:v0.1.0-3
    ```
    
    - this new image uses tfhe-rs 0.9, while the old one (version `v9` was using tfhe-rs 0.8)

## `message: "account wasm1z6rlvnjrm5nktcvt75x9yera4gu48jflhy2ysv not found"`

if you get something like : 

```jsx
2024-11-06T10:21:02.918330Z  INFO gateway::blockchain::kms_blockchain: 🍊 Decrypting ciphertexts of total size: 2082
thread 'tokio-runtime-worker' panicked at blockchain/gateway/src/blockchain/handlers.rs:37:10:
called `Result::unwrap()` on an `Err` value: Failed to broadcast transaction: status: NotFound, message: "account wasm1z6rlvnjrm5nktcvt75x9yera4gu48jflhy2ysv not found", details: [], metadata: MetadataMap { headers: {"content-type": "application/grpc", "x-cosmos-block-height": "17132221"} }

Caused by:
    status: NotFound, message: "account wasm1z6rlvnjrm5nktcvt75x9yera4gu48jflhy2ysv not found", details: [], metadata: MetadataMap { headers: {"content-type": "application/grpc", "x-cosmos-block-height": "17132221"} }
```

you most likely have a config issue with the gateway and/or the connector’s toml files.

In our case, the issue happened when running e2e test with the deployed tkms : 

- a new wallet was needed for sending transactions to marcus' deployed blockchain, for which we had a new mnemonic
- the issue was that only the connector's mnemonic (`default.toml`) was changed
- the solution was to also change it in the gateway's `gateway.toml` config file
- also, there are 2 `default.toml` config file for the connector : one in `blockchain/connector/config` and one in `blockchain/gateway/config`. Only the one in the `gateway`'s directory is used for the l1-demo
- this should be fixed in kms-core’s main, since we'll soon have multiple connectors, these settings might change a bit at one point

Another reason could be that the specified wallet never appeared in a tx before, which can happen if the tx that transfers funds from validator to other wallets in `blockchain/scripts/setu_wallets.sh` fails (e.g. due to trying to spend more than what the validator owns).

## What max byte sizes (transactions, CW storage) ?

- for transactions : default values for local testing are set by wasmd, and are basically the same as [here](https://github.com/zama-ai/kms-core-infra/blob/main/kubernetes/charts/kms-blockchain/templates/kms-blockchain-validator-config.yaml#L325):
    - max size for transaction is `1048576` bytes (1 MB)
    - max transactions in mempool is `5000` transactions
    - max total size for mempool is `1073741824` bytes (2GB)
- for storage : cosmwasm VM limits how much space a single key and value when reading/writing [here](https://github.com/CosmWasm/cosmwasm/blob/main/packages/vm/src/imports.rs#L40) :
    - max key size is `64` kb
    - max value size is `128` kb

## `test_blockchain_connector` failes with timeout

If you get something like 

```jsx
thread 'test_blockchain_connector' panicked at blockchain/connector/tests/integration_test.rs:192:18:
called `Result::unwrap()` on an `Err` value: JoinError::Panic(Id(11846), "Timeout", ...)
```

And checking logs seems to tell you that some responses are not properly sent to the blockchain :

- try to increase the `amount` for `ContractFee` in `start_sync_handler`
- else, run the test with `RUST_LOG=info` to know more about the issue
- worst case : you’ll need to check transactions within the blockchain :
    - remove `_ctx: &mut DockerComposeContext` from `test_blockchain_connector`
    - run `docker-compose -f docker-compose,yml` in `blockchain/connector/tests` (to avoid re-doing everything if your changes only touches the test itself)
    - (optional) add some `tracing::info` and run the test with `RUST_LOG=info`
    - go to the `full-node` docker container and exec `wasmd` commands in it to get more info :
        - if you have the `transactionId` , get the transaction :
            
            ```jsx
            wasmd query wasm contract-state smart '$CONTRACT_ADDR' '{"get_transaction": {"txn_id":"$TXN_ID"}}'
            ```
            
        - to get all transactions sent by the connector:
            
            ```jsx
            wasmd query txs --query "message.sender='$CONNECTOR_ADDR'"
            ```
            
            - in particular, check `raw_logs`
            - you can also see a what time these transactions were made with `timestamp`

## Building docker images fail with a requirement to use `docker login`

Trying to build docker images give the following error:

```jsx
Error response from daemon: pull access denied for tfhe-core, repository does not exist or may require 'docker login'
```

Either use [this link](https://github.com/settings/tokens) or go to your GitHub, click you profile picture, select "Settings". Then  navigate to "Developer Settings" > "Personal Access Tokens" >  "Tokens (classic)" > "Generate new token (classic)". The token should have the "read:packages" permission. Afterwards, do `docker login ghcr.io` and use your github ID and the token to login. Note that this token is saved by docker locally in the clear, so it's best to only give it the  permissions you need and set the expiration time to a short period of  time.

## adding `RUST_LOG=info` (or `trace`)does not print any logs

- try to see if there is an `init_tracing` in what you run (ex: a test)
- check if there is an `await` at the end of it :
    - if not, add it
    - try again

## Core crashes with error 137

Running the servers in docker results in a crash with something like the following:

```jsx
dev-kms-core-1-1 exited with code 137
```

This is due to Docker running out of memory. By default Docker only uses 8 GB of memory, but to run tests, even for just 4 parties. Significantly more is needed. It is recommended to increase it to 24 Gb (although the tests for 4 parties will likely work with less). 

Hence to fix the issue change your local Docker settings to ensure it has enough RAM

## Error loading from [ghcr.io](http://ghcr.io) during docker image generation

Running the following results in an error 

```jsx
docker compose -vvv -f docker-compose-core-base.yml -f docker-compose-core-threshold.yml build          
[+] Building 12.4s (8/8) FINISHED                                                  
 => [internal] load local bake definitions                                    0.0s
 => => reading from stdin 3.40kB                                              0.0s
 => [dev-kms-core-3 internal] load build definition from Dockerfile           0.0s
 => => transferring dockerfile: 4.26kB                                        0.0s
 => [dev-kms-core-certs] resolve image config for docker-image://docker.io/d  1.0s
 => CACHED [dev-kms-core-2] docker-image://docker.io/docker/dockerfile:1@sha  0.0s
 => => resolve docker.io/docker/dockerfile:1@sha256:9857836c9ee4268391bb5b09  0.0s
 => [dev-kms-core-2 internal] load metadata for docker.io/library/golang:1.2  0.7s
 => CANCELED [dev-kms-core-certs internal] load metadata for cgr.dev/chaingu  0.9s
 => ERROR [dev-kms-core-2 internal] load metadata for ghcr.io/zama-ai/kms/ru  0.9s
```

This is due to failed authentication. It can be that you have not authorized yet, or that your token is invalid, expired or do not contain the right permissions for Zama.

- First ensure you have a proper token: Go to github -> Settings → Developer Settings → Personal Access Tokens
- If there is a token then ensure that zama-ai is authorized by clicking “Configure SSO” and “Authorize” if needed.
- If no token is there, generate a new one using “Generate new token”
- On your local machine add the token for your github user

```jsx
echo '<classic PAT with Zama authorized>' | docker login ghcr.io -u <my_username> --password-stdin
```

## Error loading from cgr.dev during docker image generation

When trying to compile the docker images an error in relation to [cgr.dev](http://cgr.dev) or chainguard will be presented. 

For this to work you must ensure that you have configured a valid access toke to the chainguard images.

**⚠️ NOTE:** when you use the sign-up link it is essential to use you Zama google account *not* your github account, to sign in.

**NOTE: never** use the tokens in CI or post them in the repo or other public places. The tokens are meant for local development.

Navigate to this page [https://console.chainguard.dev/org/zama.ai/settings/pull-tokens](https://console.chainguard.dev/org/zama.ai/settings/pull-tokens) and then setup a new pull token and configure this in your command line using the suggested command after token generation. 

If you do not have owner rights, or access to chainguard then request access in the Working-tools slack channel.
