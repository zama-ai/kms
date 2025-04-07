# Tutorials

## Interaction with deployed KMS cores
To try out interaction with a deployed set of KMS cores, you can use the [`core-client`](../../core-client/README.md) to do so.
In this tutorial we'll walk you through the required steps to locally deploy a threshold KMS with 4 MPC cores, generate a set of FHE keys and run a user decryption on the KMS.
This tutorial shows you a subset of the options of the `core-client`. For more details please refer to its [README](../../core-client/README.md).

### Requirements
- Rust. Ensure you have a recent version of Rust (`v1.85` or newer) installed on your system. More information on the [official website](https://www.rust-lang.org/).
- [The protobuf compiler, `protoc`](https://protobuf.dev/installation/) must be installed and [Docker](https://docs.docker.com/engine/install/) must be installed and running.
- Ensure you have access to the required Docker images on Github.
  - While some repositories are still private, you need to setup access. For this, either use [this link](https://github.com/settings/tokens) or go to your GitHub, click you profile picture, select "Settings". Then navigate to "Developer Settings" > "Personal Access Tokens" > "Tokens (classic)" > "Generate new token (classic)". The token must have at least the "read:packages" permission.
  Afterwards, do `docker login ghcr.io` and use your github ID and the token to login. Note that this token is saved by docker locally in the clear, so it's best to only give it the permissions you need and set the expiration time to a short period of time.

### Running the threshold cores locally
The threshold KMS in its default configuration consists of 4 KMS cores that interact with each other to run the secure MPC protocols for all operations.
To run these cores locally, you can use the docker-compose file at the root of this repository: [docker-compose-core-threshold.yml](../../docker-compose-core-threshold.yml).
To start the threshold KMS components, run `docker compose -vvv -f docker-compose-core-base.yml -f docker-compose-core-threshold.yml up` at the root of the repository. This will fetch the latest images from `ghcr.io`. Optionally you can also build the images yourself with the `build` command. This will take a couple of minutes and is not required if you're fine with the pre-built ones from `ghcr.io`.
The KMS cores are running when no more logs show up (and if there are no errors). Typically the last log you see is
```
dev-kms-core-init-1   | Exiting core service init...
dev-kms-core-init-1 exited with code 0
```


### Interaction with the local KMS cores
In a different terminal, we can now interact with the running cores from the previous step.

1. First, build the `core-client` tool by running `cargo build -p kms-core-client` in the repository root. This should take about a minute or two, depending on your machine.
2. The `core-client` can be configured via a config file, where a good default is provided in [`core-client/config/client_local_threshold.toml`](../../core-client/config/client_local_threshold.toml). Optionally, if you're just interested in seeing quick results, you can switch to smaller (but insecure) testing paramters by setting
```fhe_params = "Test"```
in the config file used in the next step.
3. Then, generate a set of private and public FHE keys by running the following command, pointing to your desired config file after the `-f` flag:
    ```{bash}
    $ cargo run --bin kms-core-client -- -f core-client/config/client_local_threshold.toml -a -l insecure-key-gen
    ```
    The command will print plenty of logs and return the `key-id` that we require in the following step. The output looks like this, where `948ddb338f9279d5b06a45911be7c93dd7f45c8d6bc66c36140470432bce7e06` is the `key-id`:
    ```
    insecure keygen done - {
      "request_id": "948ddb338f9279d5b06a45911be7c93dd7f45c8d6bc66c36140470432bce7e06"
    }
    ```

4. To run a user decryption (reencryption) of the little-endian hex value `0x2342` of type `euint16` run the following command, where `key-id` is the value you reiceived in the output of step 2 (e.g. `948ddb338f9279d5b06a45911be7c93dd7f45c8d6bc66c36140470432bce7e06` above):
    ```{bash}
    $ cargo run --bin kms-core-client -- -f core-client/config/client_local_threshold.toml -a -l re-encrypt from-args --to-encrypt 0x2342 --data-type euint16 --key-id <key-id>
    ```
    If everything goes well, you will see a message telling you that the user decryption was successful, along with several status logs. The `core-client` will also validate, that the result of the cores can be reconstructed correctly.

    The output of a succesful run will end similar to the following logs:
    ```
    {"timestamp":"2025-03-26T10:59:23.195672Z","level":"INFO","fields":{"message":"Reencryption response is ok: TypedPlaintext { bytes: [35, 66], fhe_type: Euint16 } / U16(16931)"},"target":"kms_core_client"}
    {"timestamp":"2025-03-26T10:59:23.196581Z","level":"INFO","fields":{"message":"Core Client terminated successfully."},"target":"kms_core_client"}
    {"timestamp":"2025-03-26T10:59:23.196592Z","level":"INFO","fields":{"message":"Core Client command ReEncrypt(CipherParameters { to_encrypt: \"0x2342\", data_type: Euint16, compression: false, precompute_sns: false, key_id: \"948ddb338f9279d5b06a45911be7c93dd7f45c8d6bc66c36140470432bce7e06\", batch_size: 1, ciphertext_output_path: None }) took 19.267022292s."},"target":"kms_core_client"}
    Reencrypted Plaintext U16(16931) - {
      "request_id": "b400ffef1eff5de5b36d5556ff064c01f56b9c908fac29c87d4ed9d520ee7b92"
    }
    ```


{% hint style="success" %}
**Zama 5-Question Developer Survey**

We want to hear from you! Take 1 minute to share your thoughts and helping us enhance our documentation and libraries. **👉** [**Click here**](https://www.zama.ai/developer-survey) to participate.
{% endhint %}
