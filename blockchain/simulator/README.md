# Contract Execution Tool

This tool allows you to execute and query smart contracts on the KMS blockchain.
It provides a command-line interface (CLI) for interacting with a blockchain network and associated services.

## Prerequisites

- Rust (ensure you have Rust installed on your system)
- Ensure you have access to the Docker images on Github:
  - Either use [this link](https://github.com/settings/tokens) or go to your GitHub, click you profil picture, select "Settings". Then nagivate to "Developer Settings" > "Personal Access Tokens" > "Tokens (classic)" > "Generate new token (classic)". The token should have the "read:packages" permission. Afterwards, do docker login ghcr.io and use your github ID and the token to login. Note that this token is saved by docker locally in the clear, so it's best to only give it the permissions you need and set the expiration time to 7 days.
- A running KMS-blockchain, KMS connector and KMS core. There are two options:
    - Either starts a centralized or threshold instance with the docker-compose files at the root of this repository,
        - If you want to build the docker images locally, run the root of the repository `docker compose -vvv -f docker-compose-kms-base.yml -f docker-compose-kms-centralized.yml build` for the centralized case and `docker compose -vvv -f docker-compose-kms-base.yml -f docker-compose-kms-threshold.yml build` for the threshold case. Building all images takes around 20 minutes. If you want to use the latest images from ghcr.io you can skip this step.
        - Then, run `docker compose -vvv -f docker-compose-kms-base.yml -f docker-compose-kms-centralized.yml up` for the centralized case and `docker compose -vvv -f docker-compose-kms-base.yml -f docker-compose-kms-threshold.yml up` for the threshold case, at the root of the repository to start the components.
        Side note: Ensure that the following is present in an `.env` file at the root of the repository:
        ```
        MINIO_ROOT_USER=admin
        MINIO_ROOT_PASSWORD=strongadminpassword
        ```
    - Or bind the proper ports from the Kubernetes threshold namespace to your local host
        - `bash ./bind_k8_threshold.sh` in this folder
        Side note: you will also need to download the proper keys from S3 to do so you can launch the following command: `aws s3 cp s3://kms-dev-v1/ aws/ --recursive`
- A configuration file (see below)

## Configuration

To run this tool, you need a configuration file.
The file can be specified with the `-f` flag. E.g. `-f config/local_centralized.toml`.
If the file is not specified, then `./config/local_centralized.toml` will be used by default.
The simulator currently ships with the following pre-defined configurations:
    - `./config/local_centralized.toml` for the docker-compose centralized version (default)
    - `./config/local_threshold.toml` for the docker-compose threshold version
    - `./config/local_threshold_from_compose.toml` for the docker-compose threshold version run from docker compose (used for keygen when launching the gateway)
    - `./config/k8_threshold.toml` for the kubernetes threshold version
    - `./config/k8_centralized.toml` for the kubernetes centralized version

- The addresses must match the deployment of the KMS entities.

- The `mnemonic` field must match an address that has been funded with the appropriate amount of tokens to run operations. In the local deployment, this is currently the `connector` wallet.

- The `contract` address must be set to the contract that manages the KMS operations.
If you are not sure about this, then consult the Docker logs when running the simulator or simulator tests. More specifically:
1. Open Docker _while_ the simulator or a test of the simulator is running. It needs to be done while it is running as the images will be shut down and the log destroyed after the simulator is closed or test completed.
2. Go to the fan "Containers".
3. Find `zama-kms-centralized` or `zama-kms-threshold` and click on it. This opens the live log.
4. Locate `Summary of all the addresses:` issued from the container `dev-kms-blockchain-asc-deploy-1`.
5. Around the end of this log you can find the `ASC_DEBUG_ADDRESS` which is the address you should use for local testing.
6. Copy the address and paste it into the configuration file you use under `contract`.
For example:

```
dev-kms-blockchain-asc-deploy-1  | ASC_DEBUG_ADDRESS : wasm1qwlgtx52gsdu7dtp0cekka5zehdl0uj3fhp9acg325fvgs8jdzksu3v4ff
```

## Usage

1. Make sure the prerequisites above are met and that the configuration is set up correctly.
2. Clone this repository and navigate to the project directory.
3. Build the project using `cargo build`.
4. Run the tool with the desired command with the appropriate configuration file. (See below for details on commands.)

An example of configuration file for the central setup can be found ![here](./config/local_centralized.toml).

You can provide additional configuration options via a configuration file (if needed).
Use the `-f` flag to specify the path to the configuration file.
In that file you will configure the addresses of validators, contract address to interact with and mnemonic wallet.

Note that for the kubernetes version of the KMS blockchain the address of the contract will change each time  a new version is deployed.

To use the simulator with the centralized version of the KMS running through docker-compose use ./config/local.toml.
To use the simulator with the threshold version of the KMS running on Kubernetes use ./config/k8_threshold.toml.

### Insecure key-generation

Key-generation can be done insecurely using the following command:

```{bash}
$ cargo run -- -f <path-to-toml-config-file> insecure-key-gen
```

### CRS generation

A CRS can be created using the following command, where `<max-num-bits>` is the number of bits that one can proof with the CRS:

```{bash}
$ cargo run -- -f <path-to-toml-config-file> insecure-crs-gen --max-num-bits <max-num-bits>
```

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

### Validator Keyring Password
The validator keyring password is currently set to `1234567890` and is specified / can be modified in [`deploy_contracts.sh`](../scripts/deploy_contracts.sh).
