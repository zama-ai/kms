# KMS Core Client

This tool allows you to interact with the KSM cores via a command line interface.
The library can also be called for running tests.

## Prerequisites

- Rust (ensure you have Rust installed on your system)
- Ensure you have access to the Docker images on Github:
  - Either use [this link](https://github.com/settings/tokens) or go to your GitHub, click you profil picture, select "Settings". Then nagivate to "Developer Settings" > "Personal Access Tokens" > "Tokens (classic)" > "Generate new token (classic)". The token should have the "read:packages" permission. Afterwards, do `docker login ghcr.io` and use your github ID and the token to login. Note that this token is saved by docker locally in the clear, so it's best to only give it the permissions you need and set the expiration time to a short period of time.
- A running (set of) KMS cores. There are two options:
    - Either starts a centralized or threshold instance with the docker-compose files at the root of this repository,
        - If you want to build the docker images locally, run the root of the repository `docker compose -vvv -f docker-compose-core-base.yml -f docker-compose-core-centralized.yml build` for the centralized case and `docker compose -vvv -f docker-compose-core-base.yml -f docker-compose-core-threshold.yml build` for the threshold case. Building all images takes a few minutes. If you want to use the latest images from ghcr.io you can skip this step.
        - Then, run `docker compose -vvv -f docker-compose-core-base.yml -f docker-compose-core-centralized.yml up` for the centralized case and `docker compose -vvv -f docker-compose-core-base.yml -f docker-compose-core-threshold.yml up` for the threshold case, at the root of the repository to start the components.
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
The file to be used must be specified with the `-f` flag. E.g. `-f config/local_centralized.toml`.

The core client currently ships with the following pre-defined configurations:
    - `./config/client_local_centralized.toml` for the docker-compose centralized version
    - `./config/client_local_threshold.toml` for the docker-compose threshold version

- The `core_addresses` in the config toml must match the deployment of the KMS entities.

- The `s3_endpoint` in the config toml must match the S3 endpoint that is used for public data (public keys, CRS, etc.)

- For a threshold deployment the `decryption_mode` must match to what is deployed on the threshold servers. The default is `NoiseFloodSmall`.


## Usage

1. Make sure the prerequisites above are met and that the configuration is set up correctly.
2. Clone this repository and navigate to the project directory.
3. Build the project using `cargo build`.
4. Run the tool with the desired command with the appropriate configuration file. (See below for details on commands.)

An example configuration file for the centralized setup can be found ![here](./config/client_local_centralized.toml).

Use the `-f` flag to specify the path to the configuration file.

Other command line options are:
 - `-l`/`--logs`: print debug logs
 - `--max-iter`: the maximum number of retries for retrieving a computation result from the KMS
 - `-a`/`--expect-all-responses`: if set, waits for a response from all KMS cores. If not set, continue once we have enough responses, depending on the operation.
 - `-h`/`--help`: show the CLI help

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
$ cargo run -- -f <path-to-toml-config-file> decrypt --to-encrypt <hex-value-encrypt> --data-type <euint-value> --key-id <public-key-id>
```

Optional command line options for this commad are:
 - `-b`/`--batch-size`: the batch size of values to decrypt (default: 1)
 - `-c`/`--compressed`: the sent values are compressed ciphertexts (default: false)

### Re-Encrypt

```{bash}
$ cargo run -- -f <path-to-toml-config-file> re-encrypt --to-encrypt <hex-value-encrypt> --data-type <euint-value> --key-id <public-key-id>
```

Optional command line options for this commad are:
 - `-b`/`--batch-size`: the batch size of values to decrypt (default: 1)
 - `-c`/`--compressed`: the sent values are compressed ciphertexts (default: false)
