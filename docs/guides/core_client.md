# KMS Core Client

This tool allows you to interact with the KMS cores' grpc endpoints via a command line interface.
The core client library is also used for running tests.

## Prerequisites

- [Rust](https://www.rust-lang.org/tools/install). Ensure you have a recent version of Rust installed on your system. We require `v1.86` or newer.
- [The protobuf compiler, `protoc`](https://protobuf.dev/installation/) must be installed.
- [Docker](https://docs.docker.com/engine/install/) must be installed and running. IMPORTANT: Note that running the KMS servers requires a lot of RAM. So please _ensure that your Docker is setup to have at least 24 GB of RAM_. If not, the KMS nodes may exit `with code 137`.
- Ensure you have access to the required Docker images on Github:
  - Either use [this link](https://github.com/settings/tokens) or go to your GitHub, click you profile picture, select "Settings". Then navigate to "Developer Settings" > "Personal Access Tokens" > "Tokens (classic)" > "Generate new token (classic)". The token should have the "read:packages" permission. Afterwards, do `docker login ghcr.io` and use your github ID and the token to login. Note that this token is saved by docker locally in the clear, so it's best to only give it the permissions you need and set the expiration time to a short period of time.
- A running set of KMS cores (and other required components).
    There are two options: either a _centralized_ or a _threshold_ KMS instance.
    - The centralized KMS consists of a single core, that runs all operations in plain and is intended for testing or when deployed on secure hardware.
    - The threshold KMS in its default configuration consists of 4 KMS cores that interact with each other to run the secure MPC protocols for all operations.
      The configuration can be extended to more than 4 parties, by adding configurations to [`core/service/config`](../../core/service/config/) and referencing them in [docker-compose-core-threshold.yml](../../docker-compose-core-threshold.yml), analogous to the first 4 parties.
    - Both cases are managed via the docker-compose files at the root of this repository: [docker-compose-core-centralized.yml](../../docker-compose-core-centralized.yml) or [docker-compose-core-threshold.yml](../../docker-compose-core-threshold.yml).
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

You can run the KMS Core Client either natively using Cargo or via Docker.

### Native Installation

1. Make sure the prerequisites above are met and that the configuration is set up correctly.
2. Clone this repository and navigate to the project root directory.
3. Build the project using `cargo build`.
4. Run the tool with the desired command and with the appropriate configuration file. (See [below](#supported-operations) for details on commands.)

### Docker Usage

The KMS Core Client is also available as a Docker image that includes both the client and health check tools:

```bash
# Pull the latest image
docker pull ghcr.io/zama-ai/kms/core-client:latest

# Run core client with configuration
docker run -v ./core-client/config:/config \
  ghcr.io/zama-ai/kms/core-client:latest \
  kms-core-client -f /config/client_local_threshold.toml <command>

# Example: Generate insecure keys
docker run -v ./core-client/config:/config \
  --network host \
  ghcr.io/zama-ai/kms/core-client:latest \
  kms-core-client -f /config/client_local_threshold.toml insecure-key-gen
```

The Docker image also includes the **kms-health-check** tool for monitoring KMS deployments:

```bash
# Check health of running KMS instance
docker run --network host \
  ghcr.io/zama-ai/kms/core-client:latest \
  kms-health-check live --endpoint localhost:50100

# Validate KMS server configuration
docker run -v ./core/service/config:/config \
  ghcr.io/zama-ai/kms/core-client:latest \
  kms-health-check config --file /config/compose_1.toml

# Get JSON output for monitoring systems
docker run --network host \
  ghcr.io/zama-ai/kms/core-client:latest \
  kms-health-check --format json live --endpoint localhost:50100
```

See the [Health Monitoring](#health-monitoring) section below for more details on using the health check tool.


Use the `-f` flag to specify the path to the [configuration file](#configuration-file).

Other command line options are:
 - `-l`/`--logs`: print debug logs to stdout and also write a timestamped `.log` file
 - `--max-iter`: the maximum number of retries for retrieving a computation result from the KMS
 - `-a`/`--expect-all-responses`: if set, the tool waits for a response from all KMS cores. If not set, the tool continues once it has received the minimum amount of required responses, depending on the operation.
 - `-h`/`--help`: show the CLI help

## Backup and restore

Before running the KMS servers it is important to ensure a proper setup of the backup system.
Currently multiple different modes of backup are available for the KMS. However, only a single mode can be used at any given time.
Backup modes are setup through the toml configuration files (or environment variables) which are used by Docker to boot the KMS servers. 
The backups contain _all_ data stored in the private storage (except PRSS setup data) and will be automatically updated as new material is constructed. In fact, operations of the KMS will fail if the backup cannot be computed and stored (when a backup system has been set up). 
Furthermore, the backup system will auto-update at every boot. Thus changing the mode, or the filesystem of the backup, in a configuration file will be reflected at the next reboot. Thus it is easy to update the mode of backup without having to manually move existing backups. 
Backups are only meant to be used in case of an emergency. More specifically when a KMS node loses access to the private storage. 

Briefly the different backup modes are the following:
- Import/export based.
  Backups are stored on a separate file system, which may or may not, be encrypted by a key managed in AWS KMS.
- Custodian based.
  Backups can be stored in public but the keys used to decrypt the backups are secret shared between a set of custodians. Thus the custodians need to participate in order to recover. However, the custodians do not need to participate to construct a backup, since each KMS node will have a public key which they can use to encrypt the backed up data. 

Of these modes the custodian-based one is preferred. 
WARNING: If using the import/export based approach _without_ AWS KMS, then the backup WILL NOT be encrypted. This option is only allowed temporarily and should _never_ be used as an actual backup solution, but instead only as a means to support import and export of keys in case they need to be moved from one operator to another.

Both modes are setup under `[backup_vault]` in the configuration toml used by a KMS server.
Below we sketch how to setup each of these modes:

### Import/export based
#### Setup
To setup this approach (without AWS KMS) the minimum configuration may be as follows (where the local file system is used as storage):
```{toml}
[backup_vault.storage.file]
path = "./backup_vault"
```
where `./backup_vault` is the path to the where the unencrypted backup will be stored. 
Any other type of storage can also be used, such as `s3`.

To use this with AWS KMS then a keychain must also be set as follows:
```{toml}
[backup_vault.keychain.aws_kms]
root_key_id="<AWS key id>"
root_key_spec="<Key type>"
```
Where `<AWS key id>` must be replaced by the key ID from AWS KMS and `<Key type>` must be replaced by either `symm` or `asymm` depending on whether the key is symmetric or asymmetric. Of these, a setup with an `asymm` key is strongly encouraged.

For example:
```{toml}
[backup_vault.storage.s3]
bucket = "zama_kms_backup_keys"
[backup_vault.keychain.aws_kms]
root_key_id = "zama_kms_backup_root_key"
root_key_spec = "asymm"
```

#### Recovery
To recover a backup the following command can be used:
```{bash}
$ cargo run -- -f <path-to-toml-config-file> backup-restore
```
This call will take the data in the backup, decrypt (if needed), and write this to the private storage. 
However, this will _NOT_ overwrite anything on the private storage. Hence the restore operation is non-destructive and idempotent. If data in the private storage has been corrupted and that is why a restore is needed, then the corrupted data must be removed first. 
See [pitfalls](#pitfalls) below for details.

After `backup-restore` has been executed the KMS server must be rebooted for the restored data to be fetched into memory. 

### Custodian based
#### Setup
To setup a custodian based approach. A backup storage must be setup similar to the import/export approach above. However, even though this is done without additional encryption, it is safe to keep this unencrypted. For example as follows, using the local file system:
```{toml}
[backup_vault.storage.file]
path = "./backup_vault"
```

Secondly the KMS must know that the backup has to happen with the help of a set of custodians, hence the following, empty, variable must be set:
```{toml}
[backup_vault.keychain.secret_sharing]
```
Note: since this structure is empty, it is tricky to set this with an environment variable. If needed to set this with an environment variable then this can be done with a dummy value as follows: 
```{bash}
KMS_CORE__BACKUP_VAULT__KEYCHAIN__SECRET_SHARING__ENABLED=true
```

As an example of the whole setup observe the following:
```{toml}
[backup_vault.storage.file]
path = "./backup_vault"
[backup_vault.keychain.secret_sharing]
```

#### Recovery
Recovery with custodians is rather complex and requires multiple steps and manually transferring data in a trusted manner. For this reason we here walk through all the steps needed from beginning to end, in order to setup custodian based backup and recovery.

Assuming the toml file has been appropriately modified to allow custodian based backup, as discussed above, then the steps needed are as follows:

1. Setup custodians
  This first involves finding a set of custodians. Each of these must then execute a setup procedure using the KMS custodian CLI tool. 
  This tool is detailed [here](./backup.md). More specifically the setup steps are detailed [here](./backup.md#Custodian-setup).
2. Add a new custodian context
  After the custodians have executed their setup locally, then the custodian must be setup in the KMS. This will eventually happen through the gateway but can also be executed with the CLI tool as detailed in [this section](#Custodian-context).
3. Initiate the recovery.
  After step 1, the backups will be continuously kept up to date. Then when a recovery is needed, first the KMS must construct the correct data needed for the custodians in order to help decrypt this is done with the following command:
  ```{bash}
  $ cargo run -- -f <path-to-toml-config-file> custodian-recovery-init -r <dir to store recovery info from operator 1> -r <dir to store recovery info from operator 2> ...
  ```
  That is, an ordered list of arguments must be given; one for each of the KMS nodes. In monotonically increasing order of each of the KMS nodes' IDs. These directories will express where the the result of the initiation of each the servers will be stored, which must then be communicated with the custodians to proceed with the recovery.

  As a concrete example of a command for a setup with 4 servers is the following:
  ```{bash}
  $ cargo run -- -f config/client_local_threshold.toml custodian-recovery-init -r tests/data/keys/CUSTODIAN/recovery/1 -r tests/data/keys/CUSTODIAN/recovery/2 -r tests/data/keys/CUSTODIAN/recovery/3 -r tests/data/keys/CUSTODIAN/recovery/4
  ```
  As output, the custodian context/backup ID is printed. 
4. Custodians do partial decryption.
  WARNING: The recovery information of each KMS operator must be communicated _securely_ with the custodians, since at this point the KMS nodes don't have any valid keys to prove their identity on any data payload.
  Using the recovery information from the operators, each custodian can use the KMS Custodian CLI tool to prepare the partially decrypted response to the KMS nodes. Detail on this can be found in the manual for the KMS custodian tool [here](./backup.md#Recovery-(decryption-of-backup)). The results from the custodians must then be consolidated at the KMS operators. 
5. KMS nodes recover the backup decryption key.
  After the custodians have completed the partial decryption the results are communicated _individually_ to each of the KMS nodes. I.e. custodian `i` communicates the reencryption of the backup decryption key for KMS node `j` only to KMS node `j`. 
  Afterwards the KMS nodes can recover the decryption key, which can then be used to recover from the backup. The recovery of the decryption key can be done with the following command:
  ```{bash}
  $ cargo run -- -f <path-to-toml-config-file> custodian-backup-recovery -i <custodian context/backup ID> -r <dir to reencrypted decryption key from custodian 1 to operator 1> -r <dir to reencrypted decryption key from custodian 2 to operator 1> ..
  ``` 
  That is, `-i` expresses the custodian context/backup ID which helped to decrypt this. This value is given as output from `custodian-recovery-init` above. The `-r` arguments is a sorted list of the custodians partially decrypted output for each KMS node. The list must be sorted in the monotonically increasing order of the custodian per KMS node.
  As a concrete example (which allows to restore for _all_ KMS server in one go) consider the following:
  ```{bash}
  $ cargo run -- -f  config/client_local_threshold.toml custodian-backup-recovery -i 96d39b058585a54f2f46fffce7acea935bd1dcd29ca7f6d8db50abc6281f2d80 -r tests/data/keys/CUSTODIAN/response/recovery-response-1-1 -r tests/data/keys/CUSTODIAN/response/recovery-response-1-2 -r tests/data/keys/CUSTODIAN/response/recovery-response-1-3 -r tests/data/keys/CUSTODIAN/response/recovery-response-2-1 -r tests/data/keys/CUSTODIAN/response/recovery-response-2-2 -r tests/data/keys/CUSTODIAN/response/recovery-response-2-3 -r tests/data/keys/CUSTODIAN/response/recovery-response-3-1 -r tests/data/keys/CUSTODIAN/response/recovery-response-3-2 -r tests/data/keys/CUSTODIAN/response/recovery-response-3-3 -r tests/data/keys/CUSTODIAN/response/recovery-response-4-1 -r tests/data/keys/CUSTODIAN/response/recovery-response-4-2 -r tests/data/keys/CUSTODIAN/response/recovery-response-4-3
  ```
  Note: In practice it is custodians should only share the reencrypted partial decryption of a given KMS operator with that operator. I.e. all partial decryptions should not be broadcast. While each partial decryption is encrypted under an ephemeral key of a given KMS node, it is still best-practice to _not_ indiscriminantly publicize these. See [this issue](https://github.com/zama-ai/kms-internal/issues/2752).
6. Recover the backup.
  With the backup decryption key recovered in RAM, it. is now possible for the KMS nodes to decrypt the backup. This is done with the following command, similar to the import/export approach above:
  ```{bash}
  $ cargo run -- -f <path-to-toml-config-file> backup-restore
  ```
  This call will take the data in the backup and write this to the private storage. 
  However, this will _NOT_ overwrite anything in the private storage. Hence the restore operation is non-destructive. If data in the private storage has been corrupted and that is why a restore is needed, then the corrupted data must be removed first. 
  See [pitfalls](#pitfalls) below for details.
  Furthermore, observe that this will remove the decryption key from RAM. Hence the call can only be executed once. If a need arise to execute the call again then the `custodian-backup-recovery` call must be repeated. Also note that the old context should be considered burned after a restoring event and hence a new custodian context must be setup as described in step 1. 

  Consider the follow example as a concrete call:
  ```{bash}
  $ cargo run -- -f config/client_local_threshold.toml backup-restore
  ```

### Pitfalls
One subtle problem remain in restoring, regardless of using the import/export approach of the custodian approach; the fact that a KMS server cannot boot without the existence of a signing key in the private storage. Furthermore, until contexts are fully implemented, it is the case that all signing keys will have the static name `60b7070add74be3827160aa635fb255eeeeb88586c4debf7ab1134ddceb4beee`. 
Hence to allow booting the KMS server for restoring, it is recommended to use the KMS key generation tool to generate a temporary signing key s.t. the KMS server will boot. 
After the KMS server has booted the signing key should manually be removed from from the private file system such that the true signing key, which is backed up, can be restored. 

Another subtle pitfall is the fact that custodian setup messages will _only_ be valid for 1 hour for security reasons. Hence `custodian-recovery-init` will fail if the setup messages are more than 1 hour old.

Ensure that the correct KMS verification keys are used. Since keys are not overwritten things will manually have ot be deleted in order to generate new ones.

### Concrete e2e example for custodian backup
For completeness we here list all the steps needed to carry out for custodian based manual recovery. Hence this can be considered a manual feasibility test. We present these steps under the assumption that everything is running on a local machine using docker, after having checked out the source code of the project.

To further make this a manual test, make sure a [key is generated](#Key-generation) before starting step 1, and then manually delete the private shared from the KMS nodes after step 5 (i.e. remove the files at `/app/kms/core/service/keys` in the Docker images). Reboot the servers after completing all the steps and run some [decryption](#decryption) to validate the key has been restored and works properly. 

0. Ensure the KMS servers are running. 
  Ensure the latest code is compiled and start the custodian based Docker-setup images:
  ```{bash}
  cargo build
  docker compose -vvv -f docker-compose-core-base.yml -f docker-compose-core-threshold-custodian.yml build
  docker compose -vvv -f docker-compose-core-base.yml -f docker-compose-core-threshold-custodian.yml up
  ```
  Note: In case you have already been running this, old data might be present in Minio. Hence use the the Minio [webinterface](http://localhost:9001/login) to clean all old data and reboot. Use password `admin` and password `superstrongpassword`. If you don't do this, then the process might fail.
1. Setup custodians:
  In the project root run:
  ```{bash}
  cargo run --bin kms-custodian  generate --randomness 123 --custodian-role 1 --custodian-name homer-1 --path  core-client/tests/data/keys/CUSTODIAN/setup-msg/setup-1
  cargo run --bin kms-custodian  generate --randomness 123 --custodian-role 2 --custodian-name homer-2 --path  core-client/tests/data/keys/CUSTODIAN/setup-msg/setup-2
  cargo run --bin kms-custodian  generate --randomness 123 --custodian-role 3 --custodian-name homer-3 --path  core-client/tests/data/keys/CUSTODIAN/setup-msg/setup-3
  ```
  Each of these will give a seed phrase as output to the CLI. Remember these and replace them appropriately with the example ones, in the following steps. 
2. Add a new custodian context.
  In the `core-client` folder run the following:
  ```{bash}
  cargo run -- -f config/client_local_threshold.toml new-custodian-context -t 1 -m tests/data/keys/CUSTODIAN/setup-msg/setup-1 -m tests/data/keys/CUSTODIAN/setup-msg/setup-2 -m tests/data/keys/CUSTODIAN/setup-msg/setup-3
  ```
3. Initiate the recovery.
  In the `core-client` folder run the following:
  ```{bash}
  cargo run -- -f config/client_local_threshold.toml custodian-recovery-init -r tests/data/keys/CUSTODIAN/recovery/1 -r tests/data/keys/CUSTODIAN/recovery/2 -r tests/data/keys/CUSTODIAN/recovery/3 -r tests/data/keys/CUSTODIAN/recovery/4
  ```
  Take note of the ID printed on the CLI after completion.
4. Custodians do partial decryption.
  Fetch the public verification keys of the KMS nodes. With Minio these can be found at the following URLs:

  http://localhost:9000/kms/PUB-p1/VerfKey/60b7070add74be3827160aa635fb255eeeeb88586c4debf7ab1134ddceb4beee
  
  http://localhost:9000/kms/PUB-p2/VerfKey/60b7070add74be3827160aa635fb255eeeeb88586c4debf7ab1134ddceb4beee

  http://localhost:9000/kms/PUB-p3/VerfKey/60b7070add74be3827160aa635fb255eeeeb88586c4debf7ab1134ddceb4beee

  http://localhost:9000/kms/PUB-p4/VerfKey/60b7070add74be3827160aa635fb255eeeeb88586c4debf7ab1134ddceb4beee

  Download these and copy them into `core-client/tests/data/keys`. Then execute the following command in root of the KMS project, replacing the seed_phrases with the appropriate ones learned from step 1:
  ```{bash}
  cargo run --bin kms-custodian decrypt --seed-phrase "prosper wool oak moon light situate end palm sick monster clever solid" --randomness 123  --custodian-role 1 --recovery-request-path core-client/tests/data/keys/CUSTODIAN/recovery/1 --operator-verf-key core-client/tests/data/keys/PUB-p1/VerfKey/60b7070add74be3827160aa635fb255eeeeb88586c4debf7ab1134ddceb4beee --output-path core-client/tests/data/keys/CUSTODIAN/response/recovery-response-1-1
  cargo run --bin kms-custodian decrypt --seed-phrase "prosper wool oak moon light situate end palm sick monster clever solid" --randomness 123  --custodian-role 1 --recovery-request-path core-client/tests/data/keys/CUSTODIAN/recovery/2 --operator-verf-key core-client/tests/data/keys/PUB-p2/VerfKey/60b7070add74be3827160aa635fb255eeeeb88586c4debf7ab1134ddceb4beee --output-path core-client/tests/data/keys/CUSTODIAN/response/recovery-response-2-1
  cargo run --bin kms-custodian decrypt --seed-phrase "prosper wool oak moon light situate end palm sick monster clever solid" --randomness 123  --custodian-role 1 --recovery-request-path core-client/tests/data/keys/CUSTODIAN/recovery/3 --operator-verf-key core-client/tests/data/keys/PUB-p3/VerfKey/60b7070add74be3827160aa635fb255eeeeb88586c4debf7ab1134ddceb4beee --output-path core-client/tests/data/keys/CUSTODIAN/response/recovery-response-3-1
  cargo run --bin kms-custodian decrypt --seed-phrase "prosper wool oak moon light situate end palm sick monster clever solid" --randomness 123  --custodian-role 1 --recovery-request-path core-client/tests/data/keys/CUSTODIAN/recovery/4 --operator-verf-key core-client/tests/data/keys/PUB-p4/VerfKey/60b7070add74be3827160aa635fb255eeeeb88586c4debf7ab1134ddceb4beee --output-path core-client/tests/data/keys/CUSTODIAN/response/recovery-response-4-1

  cargo run --bin kms-custodian decrypt --seed-phrase "swallow around patrol toe bottom very pulse habit boy couch guide vendor" --randomness 123  --custodian-role 2 --recovery-request-path core-client/tests/data/keys/CUSTODIAN/recovery/1 --operator-verf-key core-client/tests/data/keys/PUB-p1/VerfKey/60b7070add74be3827160aa635fb255eeeeb88586c4debf7ab1134ddceb4beee --output-path core-client/tests/data/keys/CUSTODIAN/response/recovery-response-1-2
  cargo run --bin kms-custodian decrypt --seed-phrase "swallow around patrol toe bottom very pulse habit boy couch guide vendor" --randomness 123  --custodian-role 2 --recovery-request-path core-client/tests/data/keys/CUSTODIAN/recovery/2 --operator-verf-key core-client/tests/data/keys/PUB-p2/VerfKey/60b7070add74be3827160aa635fb255eeeeb88586c4debf7ab1134ddceb4beee --output-path core-client/tests/data/keys/CUSTODIAN/response/recovery-response-2-2
  cargo run --bin kms-custodian decrypt --seed-phrase "swallow around patrol toe bottom very pulse habit boy couch guide vendor" --randomness 123  --custodian-role 2 --recovery-request-path core-client/tests/data/keys/CUSTODIAN/recovery/3 --operator-verf-key core-client/tests/data/keys/PUB-p3/VerfKey/60b7070add74be3827160aa635fb255eeeeb88586c4debf7ab1134ddceb4beee --output-path core-client/tests/data/keys/CUSTODIAN/response/recovery-response-3-2
  cargo run --bin kms-custodian decrypt --seed-phrase "swallow around patrol toe bottom very pulse habit boy couch guide vendor" --randomness 123  --custodian-role 2 --recovery-request-path core-client/tests/data/keys/CUSTODIAN/recovery/4 --operator-verf-key core-client/tests/data/keys/PUB-p4/VerfKey/60b7070add74be3827160aa635fb255eeeeb88586c4debf7ab1134ddceb4beee --output-path core-client/tests/data/keys/CUSTODIAN/response/recovery-response-4-2

  cargo run --bin kms-custodian decrypt --seed-phrase "two often advance excite shiver speed vessel melt panther fiction giraffe voyage" --randomness 123  --custodian-role 3 --recovery-request-path core-client/tests/data/keys/CUSTODIAN/recovery/1 --operator-verf-key core-client/tests/data/keys/PUB-p1/VerfKey/60b7070add74be3827160aa635fb255eeeeb88586c4debf7ab1134ddceb4beee --output-path core-client/tests/data/keys/CUSTODIAN/response/recovery-response-1-3
  cargo run --bin kms-custodian decrypt --seed-phrase "two often advance excite shiver speed vessel melt panther fiction giraffe voyage" --randomness 123  --custodian-role 3 --recovery-request-path core-client/tests/data/keys/CUSTODIAN/recovery/2 --operator-verf-key core-client/tests/data/keys/PUB-p2/VerfKey/60b7070add74be3827160aa635fb255eeeeb88586c4debf7ab1134ddceb4beee --output-path core-client/tests/data/keys/CUSTODIAN/response/recovery-response-2-3
  cargo run --bin kms-custodian decrypt --seed-phrase "two often advance excite shiver speed vessel melt panther fiction giraffe voyage" --randomness 123  --custodian-role 3 --recovery-request-path core-client/tests/data/keys/CUSTODIAN/recovery/3 --operator-verf-key core-client/tests/data/keys/PUB-p3/VerfKey/60b7070add74be3827160aa635fb255eeeeb88586c4debf7ab1134ddceb4beee --output-path core-client/tests/data/keys/CUSTODIAN/response/recovery-response-3-3
  cargo run --bin kms-custodian decrypt --seed-phrase "two often advance excite shiver speed vessel melt panther fiction giraffe voyage" --randomness 123  --custodian-role 3 --recovery-request-path core-client/tests/data/keys/CUSTODIAN/recovery/4 --operator-verf-key core-client/tests/data/keys/PUB-p4/VerfKey/60b7070add74be3827160aa635fb255eeeeb88586c4debf7ab1134ddceb4beee --output-path core-client/tests/data/keys/CUSTODIAN/response/recovery-response-4-3
  ```
5. KMS nodes recover the backup decryption key.
  Execute the following from `core-client` replacing the ID following `-i` with the appropriate ID learned in step 3.
  ```{bash}
  $ cargo run -- -f  config/client_local_threshold.toml custodian-backup-recovery -i 96d39b058585a54f2f46fffce7acea935bd1dcd29ca7f6d8db50abc6281f2d80 -r tests/data/keys/CUSTODIAN/response/recovery-response-1-1 -r tests/data/keys/CUSTODIAN/response/recovery-response-1-2 -r tests/data/keys/CUSTODIAN/response/recovery-response-1-3 -r tests/data/keys/CUSTODIAN/response/recovery-response-2-1 -r tests/data/keys/CUSTODIAN/response/recovery-response-2-2 -r tests/data/keys/CUSTODIAN/response/recovery-response-2-3 -r tests/data/keys/CUSTODIAN/response/recovery-response-3-1 -r tests/data/keys/CUSTODIAN/response/recovery-response-3-2 -r tests/data/keys/CUSTODIAN/response/recovery-response-3-3   -r tests/data/keys/CUSTODIAN/response/recovery-response-4-1 -r tests/data/keys/CUSTODIAN/response/recovery-response-4-2 -r tests/data/keys/CUSTODIAN/response/recovery-response-4-3
  ```
6. Recover the backup.
  In the core-client folder execute the following command:
  ```{bash}
  $ cargo run -- -f config/client_local_threshold.toml backup-restore
  ```

## Supported Operations

### Key-generation

These commands generate a set of private and public FHE keys. It will return a `key-id` that can be used to identify the generated keys. The keys will be stored in the configured S3 bucket (or via minio locally).

#### Insecure Key-Generation
_Insecure_ key-generation can be done using the following command:

```{bash}
$ cargo run -- -f <path-to-toml-config-file> insecure-key-gen
```

This means that a single KMS core will generate a set of FHE keys in plain. In a threshold KMS, the contained private key material will then be secret shared between all KMS cores.

Note that this operation does *NOT* run a secure distributed keygen protocol, and therefore must *NOT* be used in production, as the security of the private key material cannot be guaranteed. This function is intended only for testing and debugging, to quickly generate a set of FHE keys, as the full distributed keygen protocol is very expensive and time-consuming.

It is also possible to fetch the result of an insecure key generation through its `REQUEST_ID` using the following command:
```{bash}
$ cargo run -- -f <path-to-toml-config-file> insecure-key-gen-result --request-id <REQUEST_ID>
```

Upon success, both the command to request to generate a key _and_ the command to fetch the result, will save the key material produced by the core in the `object_folder` given in the configuration file.

#### Preprocessing for Secure Key-Generation
Secure key-generation (see [below](#secure-key-generation)) requires a pre-processing step, that can be triggered via the following command:

```{bash}
$ cargo run -- -f <path-to-toml-config-file> preproc-key-gen
```
Note that this will generate large amounts of preprocessing data, which is expensive and very time-consuming (read: many hours(!) of computation on a powerful machine with many cores).

It is also possible to fetch the status of a preprocessing for key generation through its `REQUEST_ID` using the following command:
```{bash}
$ cargo run -- -f <path-to-toml-config-file> preproc-key-gen-result --request-id <REQUEST_ID>
```

Upon success, both the command to request to generate preprocessing material _and_ the command to fetch the result, will print the following: `preproc done - <REQUEST_ID>`.

#### Secure Key-Generation
Analogously to above, _secure_ key-generation can be done using the following command:

```{bash}
$ cargo run -- -f <path-to-toml-config-file> key-gen --preproc-id <PREPROC_ID>
```
Note that this will run the full distributed keygen protocol, which is expensive and time-consuming (read: several minutes of computation on a powerful machine with many cores).
This command requires a set of pre-processing information, specified via `--preproc-id <PREPROC_ID>`.

It is also possible to fetch the result of a key generation through its `REQUEST_ID` using the following command:
```{bash}
$ cargo run -- -f <path-to-toml-config-file> key-gen-result --request-id <REQUEST_ID>
```

Upon success, both the command to request to generate a key _and_ the command to fetch the result, will save the key material produced by the core in the `object_folder` given in the configuration file.

### CRS-generation

These commands compute a CRS that is used in proving and verifying ZK proofs. It will return a `crs-id` that can be used to identify the generated CRS. The CRS will be stored in the configured public S3 bucket (or via minio locally).

#### Insecure CRS-generation

A CRS can _insecurely_ be created using the following command, where `<max-num-bits>` is the number of bits that one can prove with the CRS:

```{bash}
$ cargo run -- -f <path-to-toml-config-file> insecure-crs-gen --max-num-bits <max-num-bits>
```

Note that this operation does *NOT* run a secure distributed CRS generation protocol, and therefore must *NOT* be used in production, as the security of the CRS cannot be guaranteed. This function is intended only for testing and debugging, to quickly generate a CRS, as the full distributed version is more expensive and time-consuming.

It is also possible to fetch the result of an insecure CRS generation through its `REQUEST_ID` using the following command:
```{bash}
$ cargo run -- -f <path-to-toml-config-file> insecure-crs-gen-result --request-id <REQUEST_ID>
```

Upon success, both the command to request to generate a CRS _and_ the command to fetch the result, will save the CRS produced by the core in the `object_folder` given in the configuration file.

#### Secure CRS-generation

A CRS can _securely_ be created using the following command, where `<max-num-bits>` is the number of bits that one can prove with the CRS:

```{bash}
$ cargo run -- -f <path-to-toml-config-file> crs-gen --max-num-bits <max-num-bits>
```

Note that this operation runs the secure distributed CRS generation protocol, which is more expensive and time-consuming than the insecure version above. Typically in the order of minutes.

It is also possible to fetch the result of a CRS generation through its `REQUEST_ID` using the following command:
```{bash}
$ cargo run -- -f <path-to-toml-config-file> crs-gen-result --request-id <REQUEST_ID>
```

Upon success, both the command to request to generate a CRS _and_ the command to fetch the result, will save the CRS produced by the core in the `object_folder` given in the configuration file.

#### Arguments
`<max-num-bits>` refers to the maximum bit length of the FHE types to be used in the KMS and is set to `2048` by default since 2048 is the largest number that is needed with the current types.

### Encryption

We provide a way to perform an encryption without actually sending any request to the kms-core:

```{bash}
$ cargo run -- encrypt -f <path-to-toml-config-file> --to-encrypt <hex-value-encrypt> --data-type <euint-value> --key-id <public-key-id> --ciphertext-output-path <output-file-path>
```

This allows storing the encryption to file which can then be re-used in future commands.


### Decryption

The most common use case for the KMS is to request decryptions of ciphertexts. There are two options:
 - public decryption, which returns plaintext values
 - user decryption (reencryption), which returns shares of plaintext values encrypted under a user-provided classical public key, which can then be decrypted by the user and reconstructed to the plaintext

#### Decryption / Public Decryption

To decrypt a given value of the provided FHE type, using the specified public key and then request a public decryption from the KMS cores run the following command.

Either directly from arguments provided to the cli:
```{bash}
$ cargo run -- -f <path-to-toml-config-file> public-decrypt from-args --to-encrypt <hex-value-encrypt> --data-type <euint-value> --key-id <public-key-id>
```

Or from a file generated via the _Encryption_ command described above:
```{bash}
$ cargo run -- -f <path-to-toml-config-file> public-decrypt from-file --input-path <input-file-path>
```

Note that the key must have been previously generated using the (secure or insecure) [keygen](#key-generation) above.


It is also possible to fetch the result of a decryption through its `REQUEST_ID` using the following command:
```{bash}
$ cargo run -- -f <path-to-toml-config-file> decrypt-result --request-id <REQUEST_ID>
```

Upon success, both the commands to decrypt _and_ the command to fetch the result, will result in a print of `Vec<PublicDecryptionResponse> - <REQUEST_ID>` where the `Vec` size depends on the number of received responses (specified via `num_majority` in the configuration file) for each request (specified via `--num-requests`).

Recall that `PublicDecryptionResponse` follows this format:
```proto
message PublicDecryptionResponse {
  bytes signature = 1;
  PublicDecryptionResponsePayload payload = 2;
}

message PublicDecryptionResponsePayload {
  uint32 version = 1;
  bytes verification_key = 2;
  bytes digest = 3;
  repeated bytes plaintexts = 4;
  optional bytes external_signature = 5;
}

```

#### User Decryption

Similar to public decryption, user decryption can be done as follows. To decrypt a given value of the provided FHE type, using the specified public key and then request a user decryption from the KMS cores run the following command:

Either directly from arguments provided to the cli:
```{bash}
$ cargo run -- -f <path-to-toml-config-file> user-decrypt from-args --to-encrypt <hex-value-encrypt> --data-type <euint-value> --key-id <public-key-id>
```

Or from a file generated via the _Encryption_ command described above:
```{bash}
$ cargo run -- -f <path-to-toml-config-file> user-decrypt from-file --input-path <input-file-path>
```

Upon success, the above commands print `User decrypted Plaintext <PLAINTEXT> - <REQUEST_ID>` for each request (specified via `--num-requests`).

#### Arguments
Arguments required for the public/user decryption command are:
 - `--to-encrypt <TO_ENCRYPT>` - The hex value to encrypt and request a public/user decryption. The value will be converted from a little endian hex string to a `Vec<u8>`. Can optionally have a "0x" prefix.
 - `--data-type <DATA_TYPE>` - The data type of `to_encrypt`. Expected one of `ebool`, `euint4`, ..., `euint2048`.
 - `--key-id <KEY_ID>`- The key identifier to use for public/user decryption

Optional command line options for the public/user decryption command are:
 - `-b`/`--batch-size <BATCH_SIZE>`: the batch size of values to decrypt (default: `1`). This will run the operation on `BATCH_SIZE` copies of the same message.
 - `-n`/`--num-requests <NUM_REQUESTS>`: the number of requests that are sent in parallel. This will run `NUM_REQUESTS` copies of the same request (except with a different `REQUEST_ID`)
 - `-c`/`--compression`: whether the sent values are compressed ciphertexts (default: false)
 - `--precompute-sns`: whether SNS (switch and squash) should be done prior to sending the request to the KMS,
    this can currently not to be used in combination with `---compression`, i.e.  at most one of the  `--compression` and `--precompute-sns` options can be used.
 - `--ciphertext-output-path <FILENAME>`: optionally write the ciphertext (the encryption of `to-encrypt`) to file

 __NOTE__: If the ciphertext is provided by file, then only the optional arguments `-b`/`--batch-size <BATCH_SIZE>` and `-n`/`--num-requests <NUM_REQUESTS>` are supported.

### Custodian context

In order to be able to do custodian based backup and recovery, the KMS nodes need to know the public keys of the custodians which will be able to help it recover. This is handled through custodian contexts. 
For custodian based backup we currently only support a single active custodian context. This there will only exist one set of custodians under which a backup can be constructed. Whenever a new custodian context is made, this will replace the old context as the current backup method. 
Note however that this does not remove the old backups (for safety reasons). Hence the backups _must_ be manually deleted once it has been validated that the new context works as intended. 
Below we sketch how to use the core client to create a new custodian context:
```{bash}
$ cargo run -- -f <path-to-toml-config-file> new-custodian-context -t <custodian corruption threshold> -m <dir to setup from custodian 1> -m <dir to setup from custodian 2> ...
```
The parameter `-t` specifies the corruption tolerance of the custodians. It must be less than half of the total set of custodians. The total set is inferred by the `-m` list, which expresses the paths to the setup messages of each of the custodians, sorted by their IDs in monotonically increasing order. _Note_ that the setup messages MUST have communicated securely as these contain setup information that will cryptographically authenticate the custodians later on.
See [here](./backup.md#custodian-setup) for details. 

Finally a concrete example of a command for a setup with 3 custodians is the following:
```{bash}
$ cargo run -- -f config/client_local_threshold.toml new-custodian-context -t 1 -m tests/data/keys/CUSTODIAN/setup-msg/setup-1 -m tests/data/keys/CUSTODIAN/setup-msg/setup-2 -m tests/data/keys/CUSTODIAN/setup-msg/setup-3
```


## Example Commands
- Generate a set of private and public FHE keys for testing in a threshold KMS using the default threshold config. This command will expect all responses (`-a`) and will output logs (`-l`).
    ```{bash}
    $ cargo run --bin kms-core-client -- -f core-client/config/client_local_threshold.toml -a -l insecure-key-gen
    ```
- Generate an encryption of `0x2342` of type `euint16` and ask for a user decryption from the threshold KMS using the default threshold config. This command assumes that previously an FHE key with key id `948ddb338f9279d5b06a45911be7c93dd7f45c8d6bc66c36140470432bce7e06` was created. This command will continue once it has enough responses (the `-a` flag is not provided) and will write logs (`-l`).
    ```{bash}
    $ cargo run --bin kms-core-client -- -f core-client/config/client_local_threshold.toml -l user-decrypt --to-encrypt 0x2342 --data-type euint16 --key-id 948ddb338f9279d5b06a45911be7c93dd7f45c8d6bc66c36140470432bce7e06
    ```
- Generate an encryption of `0xC0FFEE` of type `euint32` and ask for a public decryption of a batch of 3 of these ciphertexts from the threshold KMS using the default threshold config. This command assumes that previously an FHE key with key id `948ddb338f9279d5b06a45911be7c93dd7f45c8d6bc66c36140470432bce7e06` was created. This command will expect all responses (`-a`) and will write logs (`-l`).
    ```{bash}
    $ cargo run --bin kms-core-client -- -f core-client/config/client_local_threshold.toml -a -l public-decrypt --to-encrypt 0xC0FFEE --data-type euint32 -b 3 --key-id 948ddb338f9279d5b06a45911be7c93dd7f45c8d6bc66c36140470432bce7e06
    ```

## Health Monitoring

The `kms-health-check` tool (included in the Docker image) provides comprehensive health monitoring for KMS deployments:

### Features
- **Config Validation**: Validates KMS configuration files using actual server validation logic
- **Connectivity Check**: Tests gRPC endpoint connectivity and latency
- **Key Material Check**: Displays actual key IDs for FHE keys, CRS keys, and preprocessing material
- **Peer Health**: Checks connectivity to all threshold peers with detailed key information
- **JSON Output**: Machine-readable output for CI/CD and monitoring system integration

### Basic Usage

```bash
# Check health of a running KMS instance
kms-health-check live --endpoint localhost:50100

# Validate a KMS configuration file
kms-health-check config --file ./core/service/config/compose_1.toml

# Full check (config validation + live instance check)
kms-health-check full --config ./core/service/config/compose_1.toml --endpoint localhost:50100

# JSON output for monitoring systems
kms-health-check --format json live --endpoint localhost:50100

# Verbose output for debugging
kms-health-check live --endpoint localhost:50100 -vvv
```

### Docker Usage

```bash
# Check health from Docker
docker run --network host \
  ghcr.io/zama-ai/kms/core-client:latest \
  kms-health-check live --endpoint localhost:50100

# Validate configuration with volume mount
docker run -v $(pwd)/core/service/config:/config \
  ghcr.io/zama-ai/kms/core-client:latest \
  kms-health-check config --file /config/compose_1.toml

# Full check with config and live instance
docker run -v $(pwd)/core/service/config:/config \
  --network host \
  ghcr.io/zama-ai/kms/core-client:latest \
  kms-health-check full --config /config/compose_1.toml --endpoint localhost:50100
```

### Health Status Levels

- **Optimal**: All nodes online and reachable
- **Healthy**: Sufficient 2/3 majority but not all nodes online
- **Degraded**: At least threshold + 1 nodes but below 2/3 majority
- **Unhealthy**: Insufficient nodes for operations

### Integration with CI/CD

```bash
# Use in CI/CD pipelines
docker run -v $(pwd):/workspace \
  ghcr.io/zama-ai/kms/core-client:latest \
  kms-health-check config --file /workspace/config.toml || exit 1
```

### Kubernetes Health Probes

```yaml
readinessProbe:
  exec:
    command: ["/app/kms-core-client/bin/kms-health-check", "live", "--endpoint", "localhost:50100"]
  periodSeconds: 30
  timeoutSeconds: 10
```

### Exit Codes

- `0`: Success (Optimal or Healthy status)
- `1`: Warning (Degraded or Unhealthy status)
- `2`: Error (Tool execution failure)
