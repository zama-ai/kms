# KMS Core Client

This tool allows you to interact with the KMS cores' grpc endpoints via a command line interface.
The core client library is also used for running tests.

## Prerequisites

- [Rust](https://www.rust-lang.org/tools/install). Ensure you have a recent version of Rust installed on your system. We require `v1.85` or newer.
- [The protobuf compiler, `protoc`](https://protobuf.dev/installation/) must be installed.
- [Docker](https://docs.docker.com/engine/install/) must be installed and running.
- Ensure you have access to the required Docker images on Github:
  - Either use [this link](https://github.com/settings/tokens) or go to your GitHub, click you profile picture, select "Settings". Then navigate to "Developer Settings" > "Personal Access Tokens" > "Tokens (classic)" > "Generate new token (classic)". The token should have the "read:packages" permission. Afterwards, do `docker login ghcr.io` and use your github ID and the token to login. Note that this token is saved by docker locally in the clear, so it's best to only give it the permissions you need and set the expiration time to a short period of time.
- A running set of KMS cores (and other required components).
    There are two options: either a _centralized_ or a _threshold_ KMS instance.
    - The centralized KMS consists of a single core, that runs all operations in plain and is intended for testing or when deployed on secure hardware.
    - The threshold KMS in its default configuration consists of 4 KMS cores that interact with each other to run the secure MPC protocols for all operations.
      The configuration can be extended to more than 4 parties, by adding configurations to [`core/service/config`](../core/service/config/) and referencing them in [docker-compose-core-threshold.yml](../docker-compose-core-threshold.yml), analogous to the first 4 parties.
    - Both cases are managed via the docker-compose files at the root of this repository: [docker-compose-core-centralized.yml](../docker-compose-core-centralized.yml) or [docker-compose-core-threshold.yml](../docker-compose-core-threshold.yml).
    - Optional: If you want to build the docker images locally, run from the root of the repository `docker compose -vvv -f docker-compose-core-base.yml -f docker-compose-core-centralized.yml build` for the centralized case and `docker compose -vvv -f docker-compose-core-base.yml -f docker-compose-core-threshold.yml build` for the threshold case. Building all images usually takes several minutes. If you simply want to use the latest images from `ghcr.io` you can skip this step.
    - Ensure that the following is present in an `.env` file at the root of the repository:
        ```
        MINIO_ROOT_USER=admin
        MINIO_ROOT_PASSWORD=strongadminpassword
        ```
      This ensures that all entities can share public key material via minio, which emulates S3 storage locally.
    - Then, to start the KMS components, run `docker compose -vvv -f docker-compose-core-base.yml -f docker-compose-core-centralized.yml up` for the centralized case and `docker compose -vvv -f docker-compose-core-base.yml -f docker-compose-core-threshold.yml up` for the threshold case, at the root of the repository.
    - Alternatively, bind the proper ports from a Kubernetes threshold namespace to your local host
    by running `bash ./bind_k8_threshold.sh` in this folder.
    You will also need to download the proper keys from S3.
    To do so you can launch the following command: `aws s3 cp s3://kms-dev-v1/ aws/ --recursive`
- A configuration file for the core client (see [right below](#configuration-file))

## Configuration File

To run the core client you need a configuration file.
The file to be used must be specified with the `-f` flag, e.g. `-f config/client_local_centralized.toml`.

The core client currently ships with the following pre-defined configurations:
- `./config/client_local_centralized.toml` for the centralized version run via docker-compose.
- `./config/client_local_threshold.toml` for the threshold version run via docker-compose.

Values inside the toml configs are:
- `core_addresses` - A list of host names or IP addresses with ports. These must match the deployment of the KMS entities. Example: `core_addresses = ["localhost:50100","localhost:50200","localhost:50300","localhost:50400"]`.
- `s3_endpoint` - A host name or IP address, and a port. This must match the S3 endpoint that is used for public data (public keys, CRS, etc.). Example" `s3_endpoint = "http://localhost:9000/kms"`.
- `object_folder` - The list folders where public key material is stored. One per party. Example: `object_folder = ["PUB-p1","PUB-p2","PUB-p3","PUB-p4"]`.
- `num_majority` - The minimum number of matching responses required to have an honest majority.
- `num_reconstruct` - The minimum number of responses required to reconstruct a value (e.g. in user decryption).
- `decryption_mode` - For a threshold deployment this must match to what is deployed on the threshold servers. The default is `NoiseFloodSmall`.
- `fhe_params` - The set of FHE parameters to use. Can be either `Default` (for large, secure parameters) or `Test` (for smaller, insecure testing parameters).
When testing the `Test` parameters are _highly_ recommended to save time.


## Usage

1. Make sure the prerequisites above are met and that the configuration is set up correctly.
2. Clone this repository and navigate to the project root directory.
3. Build the project using `cargo build`.
4. Run the tool with the desired command and with the appropriate configuration file. (See [below](#supported-operations) for details on commands.)


Use the `-f` flag to specify the path to the [configuration file](#configuration-file).

Other command line options are:
 - `-l`/`--logs`: print debug logs to stdout and also write a timestamped `.log` file
 - `--max-iter`: the maximum number of retries for retrieving a computation result from the KMS
 - `-a`/`--expect-all-responses`: if set, the tool waits for a response from all KMS cores. If not set, the tool continues once it has received the minimum amount of required responses, depending on the operation.
 - `-h`/`--help`: show the CLI help

## Supported Operations

### Key-generation

These commands generate a set of private and public FHE keys. It will return a `key-id` that can be used to identify the generated keys. The keys will be stored in the configured S3 bucket (or via minio locally).

#### Insecure Key-Generation
_Insecure_ key-generation can be done using the following command:

```{bash}
$ cargo run -- -f <path-to-toml-config-file> insecure-key-gen
```

This means that a single KMS core will generate a set of FHE keys in plain. In a threshold KMS, the contained private key material will then be secret shared between all KMS cores.

Note that this operation does *NOT* run a secure distributed keygen protocol, and therefore must *NOT* be used in production, as the security of the private key material can not be guaranteed. This function is intended only for testing and debugging, to quickly generate a set of FHE keys, as the full distributed keygen protocol is very expensive and time-consuming.

#### Preprocessing for Secure Key-Generation
Secure key-generation (see [below](#secure-key-generation)) requires a pre-processing step, that can be triggered via the following command:

```{bash}
$ cargo run -- -f <path-to-toml-config-file> preproc-key-gen
```
Note that this will generate large amounts of preprocessing data, which is expensive and very time-consuming (read: many hours(!) of computation on a powerful machine with many cores).
This command will return a `preproc-id`.

#### Secure Key-Generation
Analogously to above, _secure_ key-generation can be done using the following command:

```{bash}
$ cargo run -- -f <path-to-toml-config-file> key-gen --preproc-id <PREPROC_ID>
```
Note that this will run the full distributed keygen protocol, which is expensive and time-consuming (read: several minutes of computation on a powerful machine with many cores).
This command requires a set of pre-processing information, specified via `--preproc-id <PREPROC_ID>`.


### CRS-generation

These commands compute a CRS that is used in proving and verifying ZK proofs. It will return a `crs-id` that can be used to identify the generated CRS. The CRS will be stored in the configured public S3 bucket (or via minio locally).

#### Insecure CRS-generation

A CRS can _insecurely_ be created using the following command, where `<max-num-bits>` is the number of bits that one can prove with the CRS:

```{bash}
$ cargo run -- -f <path-to-toml-config-file> insecure-crs-gen --max-num-bits <max-num-bits>
```

Note that this operation does *NOT* run a secure distributed CRS generation protocol, and therefore must *NOT* be used in production, as the security of the CRS can not be guaranteed. This function is intended only for testing and debugging, to quickly generate a CRS, as the full distributed version more expensive and time-consuming.

#### Secure CRS-generation

A CRS can _securely_ be created using the following command, where `<max-num-bits>` is the number of bits that one can proof with the CRS:

```{bash}
$ cargo run -- -f <path-to-toml-config-file> crs-gen --max-num-bits <max-num-bits>
```

Note that this operation runs the secure distributed CRS generation protocol, which is more expensive and time-consuming than the insecure version above. Typically in the order of minutes.

#### Arguments
`<max-num-bits>` refers to the maximum bit length of the FHE types to be used in the KMS and is set to `2048` by default since 2048 is the largest number that is needed with the current types.


### Decryption

The most common use case for the KMS is to request decryptions of ciphertexts. There are two options:
 - public decryption, which returns plaintext values
 - user decryption (reencryption), which returns shares of plaintext values encrypted under a user-provided classical public key, which can then be decrypted by the user and reconstructed to the plaintext

#### Decryption / Public Decryption

To decrypt a given value of the provided FHE type, using the specified public key and then request a public decryption from the KMS cores run the following command:

```{bash}
$ cargo run -- -f <path-to-toml-config-file> decrypt --to-encrypt <hex-value-encrypt> --data-type <euint-value> --key-id <public-key-id>
```

Note that the key must have been previously generated using the (secure or insecure) [keygen](#key-generation) above.

#### Reencryption / User Decryption

Similar to decryption, reencryption can be done as follows. To re-encrypt a given value of the provided FHE type, using the specified public key and then request a user decryption from the KMS cores run the following command:

```{bash}
$ cargo run -- -f <path-to-toml-config-file> re-encrypt --to-encrypt <hex-value-encrypt> --data-type <euint-value> --key-id <public-key-id>
```

#### Arguments
Arguments required for the decryption/reencryption command are:
 - `--to-encrypt <TO_ENCRYPT>` - The hex value to encrypt and request a decryption/re-encryption. The value will be converted from a little endian hex string to a `Vec<u8>`. Can optionally have a "0x" prefix.
 - `--data-type <DATA_TYPE>` - The data type of `to_encrypt`. Expected one of `ebool`, `euint4`, ..., `euint2048`.
 - `--key-id <KEY_ID>`- The key identifier to use for decryption/re-encryption

Optional command line options for the public/user decryption command are:
 - `-b`/`--batch-size <BATCH_SIZE>`: the batch size of values to decrypt (default: `1`). This will run the operation on `BATCH_SIZE` copies of the same message.
 - `-c`/`--compression`: whether the sent values are compressed ciphertexts (default: false)
 - `--precompute-sns`: whether SNS (switch and squash) should be done prior to sending the request to the KMS,
    this can currently not to be used in combination with `---compression`, i.e.  at most one of the  `--compression` and `--precompute-sns` options can be used.
 - `--ciphertext-output-path <FILENAME>`: optionally write the ciphertext (the encryption of `to-encrypt`) to file


## Example Commands
- Generate of a set of private and public FHE keys for testing in a threshold KMS using the default threshold config. This command will expect all responses (`-a`) and will write logs (`-l`).
    ```{bash}
    $ cargo run --bin kms-core-client -- -f core-client/config/client_local_threshold.toml -a -l insecure-key-gen
    ```
- Generate an encryption of `0x2342` of type `euint16` and ask for a user decryption of the threshold KMS using the default threshold config. This command assumes that previously an FHE key with key id `948ddb338f9279d5b06a45911be7c93dd7f45c8d6bc66c36140470432bce7e06` was created. This command will continue once it has enough responses (the `-a` flag is not provided) and will write logs (`-l`).
    ```{bash}
    $ cargo run --bin kms-core-client -- -f core-client/config/client_local_threshold.toml -l re-encrypt --to-encrypt 0x2342 --data-type euint16 --key-id 948ddb338f9279d5b06a45911be7c93dd7f45c8d6bc66c36140470432bce7e06
    ```
- Generate an encryption of `0xC0FFEE` of type `euint32` and ask for a public decryption of a batch of 3 of these ciphertexts of the threshold KMS using the default threshold config. This command assumes that previously an FHE key with key id `948ddb338f9279d5b06a45911be7c93dd7f45c8d6bc66c36140470432bce7e06` was created. This command will expect all responses (`-a`) and will write logs (`-l`).
    ```{bash}
    $ cargo run --bin kms-core-client -- -f core-client/config/client_local_threshold.toml -a -l decrypt --to-encrypt 0xC0FFEE --data-type euint32 -b 3 --key-id 948ddb338f9279d5b06a45911be7c93dd7f45c8d6bc66c36140470432bce7e06
    ```
