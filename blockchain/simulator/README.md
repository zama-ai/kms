# Contract Execution Tool

This tool allows you to execute and query smart contracts. 
It provides a command-line interface (CLI) for interacting with a blockchain network and associated services.

## Prerequisites

- Rust (ensure you have Rust installed on your system)
- A running KMS-blockchain, two options here
    - Either starts a centralized or threshold instance with the docker-compose files at the root of this repository,
        - `docker compose -vvv -f docker-compose-kms-base.yml -f docker-compose-kms-centralized.yml build` for the centralised case and `docker compose -vvv -f docker-compose-kms-base.yml -f docker-compose-kms-threshold.yml build` for the threshold case,  at the root of the repository.
        - Followed by `docker compose -vvv -f docker-compose-kms-base.yml -f docker-compose-kms-centralized.yml up`  for the centralised case and `docker compose -vvv -f docker-compose-kms-base.yml -f docker-compose-kms-threshold.yml up` for the threshold case,  at the root of the repository.
        Side note: Ensure that the following is present in an `.env` file at the root of the repository:
        ```
        MINIO_ROOT_USER=admin
        MINIO_ROOT_PASSWORD=strongadminpassword
        ```
    - Or bind the proper ports from the Kubernetes threshold namespace to your local host
        - `bash ./bind_k8_threshold.sh` in this folder
        Side note: you will also need to download the proper keys from S3 to do so you can launch the following command: `aws s3 cp s3://kms-dev-v1/ aws/ --recursive`
- Configuration file (optional, specify with `-f` flag) to match the KMS-blockchain setup
    - `./config/local.toml` for the docker-compose centralized version (default)
    - `./config/k8_threshold.toml` for the kubernetes threshold version

## Usage

1. Clone this repository and navigate to the project directory.
2. Build the project using `cargo build`.
3. Run the tool with the desired command with the appropriate configuration file.

An example of configuration file for the central setup can be found ![here](./config/local_centralized.toml).

You can provide additional configuration options via a configuration file (if needed). 
Use the `-f` flag to specify the path to the configuration file. 
In that file you will configure the addresses of validators, contract address to interact with and mnemonic wallet.

An example of configuration file can be found ![here](./config/local.toml).

Note that for the kubernetes version of the KMS blockchain the address of the contract will change each time  a new version is deployed.

To use the simulator with the centralized version of the KMS running through docker-compose use ./config/local.toml.
To use the simulator with the threshold version of the KMS running on Kubernetes use ./config/k8_threshold.toml.

### Decrypt

To encrypt a value using the public key from the configuration file and request a decryption from the KMS Blockchain.

```{bash}
$ cargo run -- -f <path-to-toml-config-file> decrypt --to-encrypt <int-value-to-encrypt-decrypt>
```

### Re-Encrypt

Re-encryption isn't supported in the simulator tool yet.

### Query Contract
<!-- TODO: Update this one -->

```{bash}
$ cargo run -- query-contract -t <txn_id> -p <proof> -o <operation>
```

- `-t` or `--txn-id`: Transaction ID for querying. This is output by previous command `execute-contract` if the command was successfully executed.
- `-p` or `--proof`: Proof of transaction validity. Same as Transaction ID
- `-o` or `--operation`: Specify the operation (e.g., `decrypt_response`, `keygen_response`, etc. See [KmsOperation](../events/kms.rs)).

### Call the faucet

<!-- TODO: Add support -->
Calling the faucet isn't supported in the simulator tool yet.
