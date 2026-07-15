# KMS Core Client

This tool allows you to interact with the KMS cores' gRPC endpoints via a command line interface.
The core client library is also used for running tests.

## Prerequisites

- [Rust](https://www.rust-lang.org/tools/install). The version pinned in [rust-toolchain.toml](../../rust-toolchain.toml) is picked up automatically by `rustup` when building inside the repository.
- [The protobuf compiler, `protoc`](https://protobuf.dev/installation/) must be installed.
- [Docker](https://docs.docker.com/engine/install/) must be installed and running. IMPORTANT: Note that running the KMS servers requires a lot of RAM. So please _ensure that your Docker is set up to have at least 24 GB of RAM_. If not, the KMS nodes may exit with `code 137`.
- Ensure you have access to the required Docker images on Github:
  - Either use [this link](https://github.com/settings/tokens) or go to your GitHub, click your profile picture, select "Settings". Then navigate to "Developer Settings" > "Personal Access Tokens" > "Tokens (classic)" > "Generate new token (classic)". The token should have the "read:packages" permission. Afterwards, do `docker login ghcr.io` and use your github ID and the token to login. Note that this token is saved by docker locally in the clear, so it's best to only give it the permissions you need and set the expiration time to a short period of time.
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
The file to be used must be specified with the `-f` flag, e.g. `-f core-client/config/client_local_centralized.toml`.

The core client currently ships with the following pre-defined configurations:
- `./config/client_local_centralized.toml` for the centralized version run via docker-compose.
- `./config/client_local_threshold.toml` for the threshold version with n=4 parties and threshold t=1 run via docker-compose.
- `./config/client_local_threshold_custodian_backup.toml` for the threshold version when executing custodian backup instructions towards a *single* KMS core from the CLI.

Values inside the TOML configs are:
- `kms_type` - The kind of KMS to interact with; "centralized" or "threshold".
- `num_majority` - The minimum number of matching responses required to have an honest majority.
- `num_reconstruct` - The minimum number of responses required to reconstruct a value (e.g. in user decryption).
- `decryption_mode` - For a threshold deployment this must match to what is deployed on the threshold servers. Valid values are `NoiseFloodSmall` (default), `NoiseFloodLarge`, `BitDecSmall`, and `BitDecLarge`.
- `fhe_params` - The set of FHE parameters to use. Can be either `Default` (for large, secure parameters) or `Test` (for smaller, insecure testing parameters).
- Each KMS core is configured under a separate `[[cores]]` section containing the following values:
  - `party_id` - The MPC party id, starting from 1 going up to n.
  - `address`- The host name or IP address and port of the cores service interface. Example: `address = "localhost:50100"`.
  - `s3_endpoint` - The host name or IP address and port of the S3 endpoint that is used for public data (public keys, CRS, etc.). Example: `s3_endpoint = "http://localhost:9000/kms"`.
  - `object_folder` - The folder on the S3 endpoint where public key material for this party is stored. Example: `object_folder = "PUB-p1"`.

When running tests, the smaller `Test` parameters are _highly_ recommended to save time.

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
PREPROC_ID=$(docker run -v ./core-client/config:/config \
  --network host \
  ghcr.io/zama-ai/kms/core-client:latest \
  kms-core-client -f /config/client_local_threshold.toml insecure-preproc-key-gen \
  | grep request_id | cut -d'"' -f4)
docker run -v ./core-client/config:/config \
  --network host \
  ghcr.io/zama-ai/kms/core-client:latest \
  kms-core-client -f /config/client_local_threshold.toml insecure-key-gen --preproc-id "$PREPROC_ID"
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
 - `-d`/`--download-all`: if set, the tool downloads the generated keys/CRSes from all KMS cores, rather than only from a single core.
 - `-h`/`--help`: show the CLI help

## Backup and recovery

Before running the KMS servers it is important to ensure a proper setup of the backup system.
Currently multiple different modes of backup are available for the KMS. However, only a single mode can be used at any given time.
Backup modes are set up through the TOML configuration files (or environment variables) which are used by Docker to boot the KMS servers.
The backups contain _all_ data stored in the private storage (except PRSS setup data) and will be automatically updated as new material is constructed. In fact, operations of the KMS will fail if the backup cannot be computed and stored (when a backup system has been set up).
Furthermore, the backup system will auto-update at every boot. Thus changing the mode, or the filesystem of the backup, in a configuration file will be reflected at the next reboot. Thus it is easy to update the mode of backup without having to manually move existing backups.
Backups are only meant to be used in case of an emergency. More specifically when a KMS node loses access to the private storage.

Briefly the different backup modes are the following:
- Import/export based.
  Backups are stored on a separate file system, which may or may not, be encrypted by a key managed in AWS KMS.
- Custodian-based.
  Backups can be stored in public but the keys used to decrypt the backups are secret shared between a set of custodians. Thus the custodians need to participate in order to recover. However, the custodians do not need to participate to construct a backup, since each KMS node will have a public key which they can use to encrypt the backed up data.

Of these modes the custodian-based one is preferred.
WARNING: If using the import/export based approach _without_ AWS KMS, then the backup WILL NOT be encrypted. This option is only allowed temporarily and should _never_ be used as an actual backup solution, but instead only as a means to support import and export of keys in case they need to be moved from one operator to another.

Both modes are set up under `[backup_vault]` in the configuration TOML used by a KMS server.
Below we sketch how to set up each of these modes:

### Import/export-based backup

#### Setup

To set up this approach (without AWS KMS) the minimum configuration may be as follows (where the local file system is used as storage):
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
$ cargo run --bin kms-core-client -- -f <path-to-toml-config-file> backup-restore
```
This call will take the data in the backup, decrypt (if needed), and write this to the private storage.
However, this will _NOT_ overwrite anything on the private storage. Hence the restore operation is non-destructive and idempotent. If data in the private storage has been corrupted and that is why a restore is needed, then the corrupted data must be removed first.

After `backup-restore` has been executed the KMS server must be rebooted for the restored data to be fetched into memory.

See [Backup restoring](#backup-restoring) below for the full command reference, including using `backup-restore` to move private material from one node to another.

### Custodian-based backup

#### Configuration

To configure custodian-based approach. A backup storage must be set up similar to the import/export approach above. However, even though this is done without additional encryption, it is safe to keep this unencrypted. For example as follows, using the local file system:
```{toml}
[backup_vault.storage.file]
path = "./backup_vault"
```

Secondly, the KMS must know that the backup has to happen with the help of a set of custodians, hence the following, empty, variable must be set:
```{toml}
[backup_vault.keychain.secret_sharing]
```
Note: since this structure is empty, it is tricky to set this with an environment variable. If this needs to be set this with an environment variable then this can be done with a dummy value as follows:
```{bash}
KMS_CORE__BACKUP_VAULT__KEYCHAIN__SECRET_SHARING__ENABLED=true
```

This environment variable must be given to the `kms-server` executable,
if the KMS is running with docker, another environment variable `KMS_DOCKER_BACKUP_SECRET_SHARING=true` must be used instead.

Here is an example configuration:
```{toml}
[backup_vault.storage.file]
path = "./backup_vault"
[backup_vault.keychain.secret_sharing]
```

#### Setup

For the custodian backup approach to work, and start doing backups, a custodian context first needs to be setup. To setup this, first a set of custodians must be selected. Each of this must complete an initialization step resulting in each of them holding a *seed phrase* and some public key material. 
The key material of each custodian must then be communicated with operators (which happens during custodian context construction). Once this is done, the operators will automatically backup private key material in a secret-shared manner, signcrypted under the custodians' public keys.
More specifically the following steps must be done:

1. Set up custodians.
  This first involves finding a set of custodians. Each of these must then execute a setup procedure using the KMS custodian CLI tool.
  This tool is detailed [here](./backup.md). More specifically the setup steps are detailed [here](./backup.md#Custodian-setup).
2. Add a new custodian context.
  After the custodians have executed their setup locally, the KMS must be made aware of those custodians. This will be done using the CLI tool as detailed in [this section](#Custodian-context).

NOTE: You may have multiple custodian contexts. However, the system will only make backups for a single custodian context. This will always be the most recent custodian context.

#### Recovery

> **WARNING — validate the `VerfKey` before starting recovery.** Recovery assumes the KMS does not have access to its private storage, so the `VerfKey` in the KMS's public storage is the trust anchor for the whole procedure. Before starting, you **must** verify that this `VerfKey` is byte-equal to the current verification key on the gateway. We do not assume the public storage is safe from modification by an adversary, so skipping this check would let an attacker substitute their own key.
> **NOTE — TLS may need be disabled during recovery** In case the loss of private data includes the `SigKey` then it is not possible for the KMS core to initialize TLS (as this key is required). Hence the KMS will boot without TLS. 

The recovery procedure allows an operator to recover their backed up private storage at any point in time _after_ the [setup phase](#setup-1) has been successfully completed.
However, the procedure is rather complex and requires multiple steps and manually transferring data in a trusted manner. For this reason, we walk through all the steps needed from the beginning to the end in order to set up custodian-based backup and recovery.

> **Note:** All custodian management and recovery commands (`new-custodian-context`, `custodian-recovery-init`, `custodian-backup-recovery`, `destroy-custodian-context`) currently operate on a **single core at a time** — the core-client errors out if the config points at more than one core. The `client_local_threshold_custodian_backup.toml` config lists exactly one core; point an equivalent single-core config at each operator you wish to back up or recover and repeat these steps.

The steps needed are as follows:
1. Initiate the recovery.
  After [setup](#setup-1), the backups will continuously be kept up to date. Then when a recovery is needed, first the KMS must construct the correct data needed for the custodians in order to help decrypt; this is done with the following command:
  ```{bash}
  $ cargo run --bin kms-core-client -- -f <single-core-config-file> custodian-recovery-init [-o <bool>]
  ```
  The optional boolean expresses whether to allow overwriting any potential existing ephemeral key (default is false, expanded parameter `overwrite-ephemeral-key`). The command prints a base64 recovery request (prefixed with `Serialized custodian result:`) which must then be communicated to the custodians to proceed with the recovery.

  As a concrete example:
  ```{bash}
  $ cargo run --bin kms-core-client -- -f core-client/config/client_local_threshold_custodian_backup.toml custodian-recovery-init
  ```
  As output, the base64 recovery request is printed. Use the custodian context ID (backup ID) from `new-custodian-context` as the `-i` argument in the next step.
1. Custodians do partial decryption.
  WARNING: The recovery information of each KMS operator must be communicated _securely_ with the custodians, since at this point the KMS nodes don't have any valid keys to prove their identity on any data payload.
  Using the base64 recovery request from the operator, each custodian uses the KMS Custodian CLI tool to prepare the partially decrypted (base64) response for the KMS node. Details on this can be found in the [manual for the KMS custodian tool](./backup.md#Recovery-(decryption-of-backup)). The base64 outputs from the custodians must then be consolidated at the KMS operator.
1. KMS node recovers the backup decryption key and restores the backup.
  After the custodians have completed the partial decryption the results are communicated _individually_ to the KMS node.
  The KMS uses the custodians recovery request to recover the backup decryption key, which it uses to restore from the backup. This is done with the following command, passing each custodian's base64 output after `-r`:
  ```{bash}
  $ cargo run --bin kms-core-client -- -f <single-core-config-file> custodian-backup-recovery -i <custodian context ID> -r "<recovery output from custodian 1>" -r "<recovery output from custodian 2>" ..
  ```
  That is, `-i` expresses the custodian context ID, which is given as output from `custodian-recovery-init` above. The `-r` arguments are the base64 partially decrypted outputs from the custodians for this KMS node (at least `t + 1` of them).
  As a concrete example:
  ```{bash}
  $ cargo run --bin kms-core-client -- -f  core-client/config/client_local_threshold_custodian_backup.toml custodian-backup-recovery -i bca56548a3913ac0067b0b84f1544cd53880eb553a71e3a29444dbf10209aba8 -r "<recovery output 1>" -r "<recovery output 2>" -r "<recovery output 3>"
  ```
  This call will take the data in the backup and write this to the private storage.
  However, this will _NOT_ overwrite anything in the private storage, nor will it delete the old backup. Hence the restore operation is non-destructive. If data in the private storage has been corrupted and that is why a restore is needed, then the corrupted data must be removed first. Furthermore, the backup will have to be removed manually after confirming successful recovery.
  Furthermore note that the old context should be considered burned after a restoring event and hence a new custodian context must be setup as described in step 1.
1. Reboot the KMS operator after the recovery, as private material is only reloaded during boot.

##### If recovery fails

- **Fewer than `t + 1` valid custodian outputs.** Reconstruction needs at least `t + 1` custodian outputs that validate against the `RecoveryValidationMaterial` in public storage. If the command rejects too many outputs (e.g. an output came from the wrong custodian role, was generated against a different recovery request, or was corrupted in transit), collect a fresh output from another custodian and re-run `custodian-backup-recovery` with the full set. Outputs are validated individually, so adding more is safe.
- **A `BackupCiphertext` fails to decrypt mid-restore.** Because the restore is non-destructive, the private storage is only ever added to, never overwritten. Remove any partially written private-storage entries, double-check that the `VerfKey` validation at the top of this section still holds, and re-run the command — already-restored entries will be skipped and the remaining ones retried.
- **Re-initiating a stuck recovery.** If recovery cannot complete, re-run `custodian-recovery-init` with `-o true` (`--overwrite-ephemeral-key`) to discard the previous in-memory ephemeral key and start a fresh recovery session, then redistribute the new recovery request to the custodians.

#### Destroy context

Destroying a custodian context permanently removes that context **and all of its backups** — both the recovery material in the operators' public storage and the `BackupCiphertext`s in the backup vault — from memory and disk. This is driven through the KMS core's `DestroyCustodianContext` endpoint (`DestroyCustodianContextRequest`, defined in [kms.v1.proto](../../core/grpc/proto/kms.v1.proto)), which takes a single argument:
- `context_id`: the custodian context ID to destroy (as returned by `new-custodian-context` when the context was created).

Two conditions must hold before destroying a context:
1. The context must be a valid custodian context that was previously created with `new-custodian-context`.
2. There must be two custodian contexts in the system to be able to remove one. Recovery is only ever possible against a non-destroyed context.

WARNING: This operation is irreversible and purges _all backups_ tied to the context. Only destroy a context once its replacement has been created and confirmed to work as intended (see [Rotating the custodian context](#rotating-the-custodian-context) below); otherwise you may be left with no usable backup.

To destroy a custodian context using the core client run the following command:
```{bash}
$ cargo run --bin kms-core-client -- -f <path-to-toml-config-file> destroy-custodian-context -i <custodian context ID>
```
The `-i`/`--custodian-context-id` argument is the ID of the custodian context to destroy, as printed by `new-custodian-context` when it was created.

As a concrete example:
```{bash}
$ cargo run --bin kms-core-client -- -f core-client/config/client_local_threshold_custodian_backup.toml destroy-custodian-context -i 0700000000000000000000000000000000000000000000000000000000000001
```

#### Rotating the custodian context
In order to rotate the custodian context the following steps must be executed
(In the following we assume there is already an existing custodian context setup):
1. Using the new set of custodians. Make a new [Custodian setup](./backup.md#Custodian-setup) and use their setup messages to setup a new custodian context on all the KMS operators. That is, execute the steps of [Setup](#setup-1).
2. After the new custodian setup has been completed successfully, and the KMS has run as expected for at least a week, you may delete the old custodian context. This is done by executing the steps in [destroy context](#destroy-context).

### Concrete e2e example for custodian backup

For completeness we here list all the steps needed to carry out for custodian-based manual recovery. Hence this can be considered a manual feasibility test. We present these steps under the assumption that everything is running on a local machine using docker, after having checked out the source code of the project.

To further make this a manual test, make sure a [key is generated](#Key-generation) before starting step 1, and then manually delete the private shared from the KMS nodes after step 5 (i.e. remove the files at `/app/kms/core/service/keys` in the Docker images). Reboot the servers after completing all the steps and run some [decryption](#decryption) to validate the key has been restored and works properly.

0. Ensure the KMS servers are running.
  Ensure the latest code is compiled and start the custodian-based Docker-setup images:
  ```{bash}
  cargo build
  docker compose -vvv -f docker-compose-core-base.yml -f docker-compose-core-threshold.yml build
  KMS_DOCKER_BACKUP_SECRET_SHARING=true docker compose -vvv -f docker-compose-core-base.yml -f docker-compose-core-threshold.yml up
  ```
  Note: In case you have already been running this, old data might be present in MinIO. Hence use the [MinIO web interface](http://localhost:9001/login) to clean all old data and reboot. Use username `admin` and password `strongadminpassword`. If you don't do this, then the process might fail.
1. Set up custodians:
  In the project root run:
  ```{bash}
  cargo run --bin kms-custodian  generate --randomness 123 --custodian-role 1 --custodian-name homer-1
  cargo run --bin kms-custodian  generate --randomness 123 --custodian-role 2 --custodian-name homer-2
  cargo run --bin kms-custodian  generate --randomness 123 --custodian-role 3 --custodian-name homer-3
  ```
  Each of these prints a seed phrase and a base64-encoded setup message (prefixed with `The custodian setup message is: `) to the CLI. Remember the seed phrases, and collect the setup messages for the next step.
2. Add a new custodian context.
  Run the following, passing each custodian's base64 setup message after `-m`:
  ```{bash}
  cargo run --bin kms-core-client -- -f core-client/config/client_local_threshold_custodian_backup.toml new-custodian-context -t 1 -i 0700000000000000000000000000000000000000000000000000000000000001 -m "<setup message 1>" -m "<setup message 2>" -m "<setup message 3>"
  ```
  > **Note:** As described in the [Recovery](#recovery-1) section, these custodian commands operate on a **single core at a time**. The `client_local_threshold_custodian_backup.toml` config used here lists exactly one core; to back up / recover another operator, point an equivalent single-core config at it and repeat these steps.

3. Initiate the recovery.
  In the `core-client` folder run the following:
  ```{bash}
  cargo run --bin kms-core-client -- -f core-client/config/client_local_threshold_custodian_backup.toml custodian-recovery-init
  ```
  This prints a base64 recovery request to the CLI (prefixed with `Serialized custodian result:`) and the custodian-context ID. Take note of both.
4. Custodians do partial decryption.
  Each custodian decrypts the base64 recovery request from step 3 and prints a base64 recovery output (prefixed with `The custodian recovery output is: `). The recovery request already carries the operator's verification key, so it no longer needs to be supplied separately. Execute the following in the root of the KMS project, replacing the seed phrases with the ones from step 1 and `<recovery request>` with the base64 string from step 3:
  ```{bash}
  cargo run --bin kms-custodian decrypt --seed-phrase "prosper wool oak moon light situate end palm sick monster clever solid" --randomness 123 --custodian-role 1 --recovery-request "<operator recovery request>"
  cargo run --bin kms-custodian decrypt --seed-phrase "swallow around patrol toe bottom very pulse habit boy couch guide vendor" --randomness 123 --custodian-role 2 --recovery-request "<operator recovery request>"
  cargo run --bin kms-custodian decrypt --seed-phrase "two often advance excite shiver speed vessel melt panther fiction giraffe voyage" --randomness 123 --custodian-role 3 --recovery-request "<operator recovery request>"
  ```
5. KMS node recovers the backup decryption key.
  Execute the following from `core-client`, replacing the ID following `-i` with the custodian-context ID from step 3 and each `<custodian recovery output>` with a base64 output from step 4 (at least `t + 1` of them):
  ```{bash}
  $ cargo run --bin kms-core-client -- -f core-client/config/client_local_threshold_custodian_backup.toml custodian-backup-recovery -i 0700000000000000000000000000000000000000000000000000000000000001 -r "<custodian recovery output 1>" -r "<custodian recovery output 2>" -r "<custodian recovery output 3>"
  ```
  The backup is restored automatically as part of this step.

## Supported Operations

### Key-generation

These commands generate a set of private and public FHE keys. It will return a `key-id` that can be used to identify the generated keys. The keys will be stored in the configured S3 bucket (or via minio locally).

#### Insecure Key-Generation

_Insecure_ key-generation can be done using the following command:

```{bash}
$ cargo run --bin kms-core-client -- -f <path-to-toml-config-file> insecure-key-gen --preproc-id <REQUEST_ID> [--uncompressed]
```

Required arguments:
 - `-i`/`--preproc-id <REQUEST_ID>`: ID of an existing preprocessing entry to consume (see [below](#insecure-dummy-preprocessing)). In threshold mode this must come from `insecure-preproc-key-gen`; in centralized mode either preprocessing endpoint can be used.

Optional arguments:
 - `-u`/`--uncompressed`: Generate legacy uncompressed public key material (`PublicKey` + `ServerKey`). By default key generation stores compressed key material.

This means that a single KMS core will generate a set of FHE keys in plain. In a threshold KMS, the contained private key material will then be secret shared between all KMS cores.

Note that this operation does *NOT* run a secure distributed keygen protocol, and therefore must *NOT* be used in production, as the security of the private key material cannot be guaranteed. This function is intended only for testing and debugging, to quickly generate a set of FHE keys, as the full distributed keygen protocol is very expensive and time-consuming.

It is also possible to fetch the result of an insecure key generation through its `REQUEST_ID` using the following command:
```{bash}
$ cargo run --bin kms-core-client -- -f <path-to-toml-config-file> insecure-key-gen-result --request-id <REQUEST_ID> [--uncompressed] [--context-id <CONTEXT_ID>] [--epoch-id <EPOCH_ID>] [--no-verify]
```

Optional arguments:
 - `-u`/`--uncompressed`: Fetch legacy uncompressed public key material instead of the default compressed keyset.
 - `--context-id <CONTEXT_ID>`: Context ID the original request was made with, used to derive the `extra_data` the external signature is bound to. Defaults to the built-in default context when omitted; must match the context of the original request or verification fails.
 - `--epoch-id <EPOCH_ID>`: Epoch ID the original request was made with, used to derive the `extra_data` the external signature is bound to. Defaults to the built-in default epoch when omitted; must match the epoch of the original request or verification fails.
 - `--no-verify`: Skip verification of the external signature and just download the material.

Upon success, both the command to request to generate a key _and_ the command to fetch the result, will save the key material produced by the core in the `object_folder` given in the configuration file.

#### Insecure (Dummy) Preprocessing

Like the secure flow, an insecure key-generation consumes a preprocessing entry, but the insecure preprocessing is a dummy: no correlated randomness is generated and only metadata such as the request ID, parameters, and external signature is recorded, so the call completes almost instantly. It can be triggered explicitly via:

```{bash}
$ cargo run --bin kms-core-client -- -f <path-to-toml-config-file> insecure-preproc-key-gen [--context-id <CONTEXT_ID>] [--epoch-id <EPOCH_ID>]
```

Optional arguments:
 - `--context-id <CONTEXT_ID>`: the context ID to use for the preprocessing. Defaults to the default context if not specified.
 - `--epoch-id <EPOCH_ID>`: the epoch ID to use for the preprocessing. Defaults to the default epoch if not specified.

The resulting `REQUEST_ID` must then be passed to `insecure-key-gen` via `--preproc-id`. Each entry is consumed by the key generation, so a fresh preprocessing is needed for each insecure key-generation call.

Note that in the threshold setting an insecure preprocessing entry can only be consumed by `insecure-key-gen`, and a secure preprocessing entry only by `key-gen`; in the centralized setting both preprocessing variants are dummy entries and are interchangeable.

It is also possible to fetch the status of an insecure preprocessing through its `REQUEST_ID` using the following command:
```{bash}
$ cargo run --bin kms-core-client -- -f <path-to-toml-config-file> insecure-preproc-key-gen-result --request-id <REQUEST_ID>
```

#### Preprocessing for Secure Key-Generation

#### Secure Preprocessing
Secure key-generation (see [below](#secure-key-generation)) requires a pre-processing step, that can be triggered via the following command:

```{bash}
$ cargo run --bin kms-core-client -- -f <path-to-toml-config-file> preproc-key-gen [--context-id <CONTEXT_ID>] [--epoch-id <EPOCH_ID>]
```

Optional arguments:
 - `--context-id <CONTEXT_ID>`: the context ID to use for the preprocessing. Defaults to the default context if not specified.
 - `--epoch-id <EPOCH_ID>`: the epoch ID to use for the preprocessing. Defaults to the default epoch if not specified.

Note that this will generate large amounts of preprocessing data, which is expensive and very time-consuming (read: many hours(!) of computation on a powerful machine with many cores).

It is also possible to fetch the status of a preprocessing for key generation through its `REQUEST_ID` using the following command:
```{bash}
$ cargo run --bin kms-core-client f-- -f <path-to-toml-config-file> preproc-key-gen-result --request-id <REQUEST_ID>
```

Upon success, both the command to request to generate preprocessing material _and_ the command to fetch the result, will print the following: `preproc done - <REQUEST_ID>`.

#### Partial (Insecure) Preprocessing
Due to how long the preprocessing phase can take, we also provide a way to perform only partially the preprocessing phase.
One can thus specify the percentage of the offline phase that should run, as well as whether at the end of this partial preprocessing we want to store a _dummy_ (__insecure__) preprocessing to be able to run the Key-Generaiton phase nonetheless.
Partial preprocessing can be triggered via the following command:

```{bash}
$ cargo run --bin kms-core-client -- -f <path-to-toml-config-file> partial-preproc-key-gen --percentage-offline <percentage_to_run> [--store-dummy-preprocessing] [--context-id <CONTEXT_ID>] [--epoch-id <EPOCH_ID>]
```

Optional arguments:
 - `--store-dummy-preprocessing`: add this flag if the insecure dummy preprocessing should stored, to be used in a key gen.
 - `--context-id <CONTEXT_ID>`: the context ID to use for the preprocessing. Defaults to the default context if not specified.
 - `--epoch-id <EPOCH_ID>`: the epoch ID to use for the preprocessing. Defaults to the default epoch if not specified.


#### Secure Key-Generation

Analogously to above, _secure_ key-generation can be done using the following command:

```{bash}
$ cargo run --bin kms-core-client -- -f <path-to-toml-config-file> key-gen --preproc-id <PREPROC_ID> [--uncompressed]
```
Note that this will run the full distributed keygen protocol, which is expensive and time-consuming (read: several minutes of computation on a powerful machine with many cores).
This command requires a set of pre-processing information, specified via `--preproc-id <PREPROC_ID>`.

Optional arguments:
 - `-u`/`--uncompressed`: Generate legacy uncompressed public key material (`PublicKey` + `ServerKey`). By default key generation stores compressed key material.
 - `--existing-keyset-id <OLD_KEY_ID>`: generate a new keyset from the secret shares of an existing keyset.
 - `--use-existing-key-tag`: when used with `--existing-keyset-id`, reuse the existing keyset's tag instead of the new key ID as tag.
 - `--copy-compressed-key-to-original`: when used with `--existing-keyset-id` and compressed keygen, copy the migrated compressed key material back to the existing keyset ID.

To migrate an existing keyset to the compressed storage layout while preserving the old key ID, run secure key generation from existing shares and ask the KMS to copy the compressed material back to the original ID:

```{bash}
$ cargo run --bin kms-core-client -- -f <path-to-toml-config-file> key-gen \
    --preproc-id <PREPROC_ID> \
    --existing-keyset-id <OLD_KEY_ID> \
    --use-existing-key-tag \
    --copy-compressed-key-to-original
```

After this migration completes, the old key ID can be used without `--uncompressed`; the client will fetch the compressed keyset and standalone public key for that old ID.

It is also possible to fetch the result of a key generation through its `REQUEST_ID` using the following command:
```{bash}
$ cargo run --bin kms-core-client -- -f <path-to-toml-config-file> key-gen-result --request-id <REQUEST_ID> [--uncompressed] [--context-id <CONTEXT_ID>] [--epoch-id <EPOCH_ID>] [--no-verify]
```

Optional arguments:
 - `-u`/`--uncompressed`: Fetch legacy uncompressed public key material instead of the default compressed keyset.
 - `--context-id <CONTEXT_ID>`: Context ID the original request was made with, used to derive the `extra_data` the external signature is bound to. Defaults to the built-in default context when omitted; must match the context of the original request or verification fails.
 - `--epoch-id <EPOCH_ID>`: Epoch ID the original request was made with, used to derive the `extra_data` the external signature is bound to. Defaults to the built-in default epoch when omitted; must match the epoch of the original request or verification fails.
 - `--no-verify`: Skip verification of the external signature and just download the material.

Upon success, both the command to request to generate a key _and_ the command to fetch the result, will save the key material produced by the core in the `object_folder` given in the configuration file.

### CRS-generation

These commands compute a CRS that is used in proving and verifying ZK proofs. It will return a `crs-id` that can be used to identify the generated CRS. The CRS will be stored in the configured public S3 bucket (or via minio locally).

#### Insecure CRS-generation

A CRS can _insecurely_ be created using the following command, where `<max-num-bits>` is the number of bits that one can prove with the CRS:

```{bash}
$ cargo run --bin kms-core-client -- -f <path-to-toml-config-file> insecure-crs-gen --max-num-bits <max-num-bits>
```

Note that this operation does *NOT* run a secure distributed CRS generation protocol, and therefore must *NOT* be used in production, as the security of the CRS cannot be guaranteed. This function is intended only for testing and debugging, to quickly generate a CRS, as the full distributed version is more expensive and time-consuming.

It is also possible to fetch the result of an insecure CRS generation through its `REQUEST_ID` using the following command:
```{bash}
$ cargo run --bin kms-core-client -- -f <path-to-toml-config-file> insecure-crs-gen-result --request-id <REQUEST_ID> [--context-id <CONTEXT_ID>] [--epoch-id <EPOCH_ID>] [--no-verify]
```

Optional arguments:
 - `--context-id <CONTEXT_ID>`: Context ID the original request was made with, used to derive the `extra_data` the external signature is bound to. Defaults to the built-in default context when omitted; must match the context of the original request or verification fails.
 - `--epoch-id <EPOCH_ID>`: Epoch ID the original request was made with, used to derive the `extra_data` the external signature is bound to. Defaults to the built-in default epoch when omitted; must match the epoch of the original request or verification fails.
 - `--no-verify`: Skip verification of the external signature and just download the material.

Upon success, both the command to request to generate a CRS _and_ the command to fetch the result, will save the CRS produced by the core in the `object_folder` given in the configuration file.

#### Secure CRS-generation

A CRS can _securely_ be created using the following command, where `<max-num-bits>` is the number of bits that one can prove with the CRS:

```{bash}
$ cargo run --bin kms-core-client -- -f <path-to-toml-config-file> crs-gen --max-num-bits <max-num-bits>
```

Note that this operation runs the secure distributed CRS generation protocol, which is more expensive and time-consuming than the insecure version above. Typically in the order of minutes.

It is also possible to fetch the result of a CRS generation through its `REQUEST_ID` using the following command:
```{bash}
$ cargo run --bin kms-core-client -- -f <path-to-toml-config-file> crs-gen-result --request-id <REQUEST_ID> [--context-id <CONTEXT_ID>] [--epoch-id <EPOCH_ID>] [--no-verify]
```

Optional arguments:
 - `--context-id <CONTEXT_ID>`: Context ID the original request was made with, used to derive the `extra_data` the external signature is bound to. Defaults to the built-in default context when omitted; must match the context of the original request or verification fails.
 - `--epoch-id <EPOCH_ID>`: Epoch ID the original request was made with, used to derive the `extra_data` the external signature is bound to. Defaults to the built-in default epoch when omitted; must match the epoch of the original request or verification fails.
 - `--no-verify`: Skip verification of the external signature and just download the material.

Upon success, both the command to request to generate a CRS _and_ the command to fetch the result, will save the CRS produced by the core in the `object_folder` given in the configuration file.

### Backup restoring

> This section is the command reference for the `backup-restore` command used by the **import/export-based** backup mode. For how to set that mode up, and for the alternative custodian-based mode, see [Backup and recovery](#backup-and-recovery) above.

If a backup vault is specified in the server configuration toml file, then all non-volatile private key material (i.e. what is stored in the private vault) is backed up to this location. This also means that it is possible to restore this content in case access to the private vault is lost, or that the private vault needs to be moved.
This is done through the backup recovery command:

```{bash}
$ cargo run --bin kms-core-client -- -f <path-to-toml-config-file> backup-restore
```

Note that this operation will copy the content from the backup vault to the private vault. In case any of the backed up content already exists in the private vault, then the request will fail.
After restoring you *must* reboot the KMS server before the restored data can be used.

This can be used to move private information from one node to another. More specifically; by constructing a temporary backup vault shared between the old and new node will ensure the relevant private information gets placed in the vault. Then when the new node wish to take over, they will use the backup restoring command to move the private information into their own private storage. Afterwards they can construct a new, private, backup vault and the shared backup vault can be destroyed.

WARNING: The backup vault is NOT encrypted by default, unless a relevant AWS KMS configuration is used.

### Encryption

We provide a way to perform an encryption without actually sending any request to the kms-core:

```{bash}
$ cargo run --bin kms-core-client -- -f <path-to-toml-config-file> encrypt --to-encrypt <hex-value-encrypt> --data-type <euint-value> --key-id <public-key-id> --ciphertext-output-path <output-file-path>
```

This allows storing the encryption to file which can then be re-used in future commands.


### Decryption

The most common use case for the KMS is to request decryptions of ciphertexts. There are two options:
 - public decryption, which returns plaintext values
 - user decryption (reencryption), which returns shares of plaintext values encrypted under a user-provided classical public key, which can then be decrypted by the user and reconstructed to the plaintext

#### Public Decryption

To decrypt a given value of the provided FHE type, using the specified public key and then request a public decryption from the KMS cores run the following command.

Either directly from arguments provided to the cli:
```{bash}
$ cargo run --bin kms-core-client -- -f <path-to-toml-config-file> public-decrypt from-args --to-encrypt <hex-value-encrypt> --data-type <euint-value> --key-id <public-key-id>
```

Or from a file generated via the _Encryption_ command described above:
```{bash}
$ cargo run --bin kms-core-client -- -f <path-to-toml-config-file> public-decrypt from-file --input-path <input-file-path>
```

Note that the key must have been previously generated using the (secure or insecure) [keygen](#key-generation) above.


It is also possible to fetch the result of a public decryption through its `REQUEST_ID` using the following command:
```{bash}
$ cargo run --bin kms-core-client -- -f <path-to-toml-config-file> public-decrypt-result --request-id <REQUEST_ID> [--handle <HANDLE>]... [--context-id <CONTEXT_ID>] [--epoch-id <EPOCH_ID>] [--no-verify]
```

Optional arguments:
 - `--handle <HANDLE>`: External ciphertext handle (hex-encoded, optionally with a "0x" prefix) from the original request, used to verify the external signature. Repeat the flag once per ciphertext in the batch. Required unless `--no-verify` is set, since handles are request-specific and cannot be defaulted from the config; the command fails when they are omitted.
 - `--context-id <CONTEXT_ID>`: Context ID the original request was made with, used to derive the `extra_data` the external signature is bound to. Defaults to the built-in default context when omitted; must match the context of the original request or verification fails.
 - `--epoch-id <EPOCH_ID>`: Epoch ID the original request was made with, used to derive the `extra_data` the external signature is bound to. Defaults to the built-in default epoch when omitted; must match the epoch of the original request or verification fails.
 - `--no-verify`: Skip all verification of the fetched responses (both the internal KMS-node signatures and the external signature) and just return them.

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

To decrypt a given value of the provided FHE type, using the specified public key, run the following command:

Either directly from arguments provided to the cli:
```{bash}
$ cargo run --bin kms-core-client -- -f <path-to-toml-config-file> user-decrypt from-args --to-encrypt <hex-value-encrypt> --data-type <euint-value> --key-id <public-key-id>
```

Or from a file generated via the _Encryption_ command described above:
```{bash}
$ cargo run --bin kms-core-client -- -f <path-to-toml-config-file> user-decrypt from-file --input-path <input-file-path>
```

Upon success, the above commands print the decrypted plaintext. To run a fixed-rate load test, provide both `--rate` and `--duration`.

#### Arguments
Arguments required for public and user decryption from args are:
 - `--to-encrypt <TO_ENCRYPT>` - The hex value to encrypt and decrypt. The value will be converted from a little endian hex string to a `Vec<u8>`. Can optionally have a "0x" prefix.
 - `--data-type <DATA_TYPE>` - The data type of `to_encrypt`. Expected one of `ebool`, `euint4`, ..., `euint2048`.
 - `--key-id <KEY_ID>`- The key identifier to use for decryption

Options shared by public and user decryption are:
 - `-b`/`--batch-size <BATCH_SIZE>`: the batch size of values to decrypt (default: `1`). This will run the operation on `BATCH_SIZE` copies of the same message.
 - `--no-compression` / `--nc`: Disables ciphertext compression, resulting in the transmission of larger uncompressed ciphertexts (default: False = compression enabled)
 - `--no-precompute-sns` / `--ns`: Disables precomputation of the switch and squash on the core client. Setting this flag causes transmission of smaller ciphertexts and runs the SnS computation on the cores. (default: False = SnS precomputation enabled)
 - `--context-id <CONTEXT_ID>`: optionally specify the context ID to use for the decryption. Defaults to the default context if not specified.
 - `--epoch-id <EPOCH_ID>`: optionally specify the epoch ID to use for the decryption. Defaults to the default epoch if not specified.

Public-decrypt-only options are:
 - `-n`/`--num-requests <NUM_REQUESTS>`: the number of requests that are sent in total. This will create `NUM_REQUESTS` copies of the same request (each with a different `REQUEST_ID`)
 - `--ciphertext-output-path <FILENAME>`: optionally write the ciphertext (the encryption of `to-encrypt`) to file
 - `-i`/`--inter-request-delay-ms <DELAY>`: delay in milliseconds between consecutive decrypt requests (default: `0`, i.e. no waiting between requests)
 - `-p`/`--parallel-requests <NUM>`: number of requests to be sent in parallel before waiting `<DELAY>` specified with `-i` (default: `0`, i.e. all requests are sent at once)

User-decrypt-only options are:
 - `--rate <REQUESTS_PER_SECOND>`: request launch rate. Must be used together with `--duration`.
 - `--duration <SECONDS>`: load-test duration. Must be used together with `--rate`.
 - `--max-in-flight <NUM>`: optional rate-mode cap for in-flight requests before the client starts shedding requests.

 __NOTE__: For public decrypt from file, only `-b`/`--batch-size <BATCH_SIZE>`, `-n`/`--num-requests <NUM_REQUESTS>`, `--inter-request-delay-ms <DELAY>`, and `-p`/`--parallel-requests <NUM>` are supported. For user decrypt from file, only `-b`/`--batch-size <BATCH_SIZE>`, `--rate <REQUESTS_PER_SECOND>`, `--duration <SECONDS>`, and `--max-in-flight <NUM>` are supported.

### Custodian context

> This section is the command reference for `new-custodian-context`. For where it fits in the end-to-end custodian backup flow — custodian setup, recovery, context rotation and destruction — see [Custodian-based backup](#custodian-based-backup) under [Backup and recovery](#backup-and-recovery) above.

In order to be able to do custodian-based backup and recovery, the KMS nodes need to know the public keys of the custodians which will be able to help it recover. This is handled through custodian contexts.
Multiple custodian contexts may exist at once, but only a single one is *active* at any given time: backups are always constructed under the most recent custodian context. Whenever a new custodian context is made, it becomes the active context and replaces the previous one as the current backup method.
Note however that this does not remove the old backups (for safety reasons). Hence the backups _must_ be manually deleted once it has been validated that the new context works as intended (see [Destroy context](#destroy-context)).
Below we sketch how to use the core client to create a new custodian context:
```{bash}
$ cargo run --bin kms-core-client -- -f <path-to-toml-config-file> new-custodian-context -t <custodian corruption threshold> -i <MPC context ID> -m "<setup message from custodian 1>" -m "<setup message from custodian 2>" ...
```
The parameter `-t`/`threshold` specifies the corruption tolerance of the custodians. It must be less than half of the total set of custodians. The total set is inferred by the `-m`/`setup_msgs` list, which expresses the base64 setup messages of each of the custodians (as printed by `kms-custodian generate`), sorted by their IDs in monotonically increasing order. _Note_ that the setup messages MUST have been communicated securely as these contain setup information that will cryptographically authenticate the custodians later on.
Note: the parameter `-i`/`--mpc-context-id` specifies the *MPC context ID* to be used for the custodian context. As a result of the command the core client will print the *custodian context ID*.
See [the custodian setup section](./backup.md#custodian-setup) for details.

Finally a concrete example of a command for a setup with 3 custodians is the following:
```{bash}
$ cargo run --bin kms-core-client -- -f core-client/config/client_local_threshold_custodian_backup.toml new-custodian-context -t 1 -i 0700000000000000000000000000000000000000000000000000000000000001 -m "<setup message 1>" -m "<setup message 2>" -m "<setup message 3>"
```

### New Epoch (Resharing)

The `new-epoch` command creates a new epoch within a given context, performing a reshare of private key material.
This can be used when some parties crashed during the DKG process so that __all__ parties (including the one that failed during DKG) can hold a share of the secret keys, or when we want to refresh key shares as a pro-active security measure.

Before executing a new epoch, the TFHE public key material must be present in the public storage of all the parties.
The kms core locally checks for existence of the public key material, and if it is missing, will attempt to automatically fetch it from its peers.
If this fails for some reason, this material needs to be copied manually to the core's storage beforehand.

```{bash}
$ cargo run --bin kms-core-client -- -f <path-to-toml-config-file> new-epoch --new-epoch-id <EPOCH_ID> --new-context-id <CONTEXT_ID> [--previous-epoch-params "context_id:<PREV_CONTEXT_ID>;epoch-id:<PREV_EPOCH_ID>;previous_keys:[key_id=<KEY_ID>,preproc_id=<PREPROC_ID>,server_key_digest=<DIGEST>,public_key_digest=<DIGEST>;key_id=<KEY_ID>,preproc_id=<PREPROC_ID>,xof_key_digest=<DIGEST>];previous_crs:[crs_id:<CRS_ID>,digest=<CRS_DIGEST>]"]
```

Required arguments:
 - `--new-epoch-id <EPOCH_ID>`: the ID of the epoch to be created.
 - `--new-context-id <CONTEXT_ID>`: the context ID for which the new epoch is created.

Optional argument `--previous-epoch-params` (for resharing from a previous epoch).
 - `context-id <PREV_CONTEXT_ID>`: the context ID of the previous epoch.
 - `epoch-id <PREV_EPOCH_ID>`: the epoch ID of the previous epoch.
 - `previous_keys`: An array (enclosed in square brackets) with the information about the keys to reshare (each key is separated by a semicolon, each information concerning a key is separated by a coma):
    - `key_id <KEY_ID>`: the ID of the key
    - `preproc_id <PREPROC_ID>`: the preprocessing ID used to generate the key.
    - `server_key_digest <DIGEST>`: the hex-encoded server key digest to use for resharing (if the key is not compressed).
    - `public_key_digest <DIGEST>`: the hex-encoded public key digest to use for resharing (if the key is not compressed).
    - `xof_key_digest <DIGEST>`: the hex-encoded xof key digest to use for resharing (if the key is compressed)
 - `previous_crs`: An array (enclosed in square brackets) with the information about the CRSes to re-sign (each CRS is separated by a semicolon, each information concerning a CRS is separated by a coma):
    - `crs_id <CRS_ID>`: The ID of the CRS
    - `digest <DIGEST>`: the hex-encoded CRS digest

#### Destroying an MPC Epoch

```{bash}
$ cargo run --bin kms-core-client -- -f <path-to-toml-config-file> destroy-mpc-epoch --epoch-id <EPOCH_ID>
```

### MPC Context Management

#### Creating a new MPC Context

A new MPC context can be created from a serialized context file or a TOML context file:

```{bash}
$ cargo run --bin kms-core-client -- -f <path-to-toml-config-file> new-mpc-context serialized-context-path --input-path <path-to-context-file>
$ cargo run --bin kms-core-client -- -f <path-to-toml-config-file> new-mpc-context context-toml --input-path <path-to-context-toml>
```

#### Destroying an MPC Context

```{bash}
$ cargo run --bin kms-core-client -- -f <path-to-toml-config-file> destroy-mpc-context --context-id <CONTEXT_ID>
```

### Retrieving Operator Public Key

To retrieve the operator public keys from the KMS cores:

```{bash}
$ cargo run --bin kms-core-client -- -f <path-to-toml-config-file> get-operator-public-key
```

This prints the public key for each configured core.

## Example Commands

- Generate a set of private and public FHE keys for testing in a threshold KMS using the default threshold config. This command will expect all responses (`-a`) and will output logs (`-l`).
    ```{bash}
    $ PREPROC_ID=$(cargo run --bin kms-core-client -- -f core-client/config/client_local_threshold.toml -a -l insecure-preproc-key-gen | grep request_id | cut -d'"' -f4)
    $ cargo run --bin kms-core-client -- -f core-client/config/client_local_threshold.toml -a -l insecure-key-gen --preproc-id "$PREPROC_ID"
    ```
- Generate an encryption of `0x2342` of type `euint16` and ask for one user decryption from the threshold KMS using the default threshold config. This command assumes that previously an FHE key with key id `948ddb338f9279d5b06a45911be7c93dd7f45c8d6bc66c36140470432bce7e06` was created. This command will continue once the request has enough responses (the `-a` flag is not provided) and will write logs (`-l`).
    ```{bash}
    $ cargo run --bin kms-core-client -- -f core-client/config/client_local_threshold.toml -l user-decrypt from-args --to-encrypt 0x2342 --data-type euint16 --key-id 948ddb338f9279d5b06a45911be7c93dd7f45c8d6bc66c36140470432bce7e06
    ```
- Generate an encryption of `0xC0FFEE` of type `euint32` and ask for a public decryption of a batch of 3 of these ciphertexts from the threshold KMS using the default threshold config. This command assumes that previously an FHE key with key id `948ddb338f9279d5b06a45911be7c93dd7f45c8d6bc66c36140470432bce7e06` was created. This command will expect all responses (`-a`) and will write logs (`-l`).
    ```{bash}
    $ cargo run --bin kms-core-client -- -f core-client/config/client_local_threshold.toml -a -l public-decrypt from-args --to-encrypt 0xC0FFEE --data-type euint32 -b 3 --key-id 948ddb338f9279d5b06a45911be7c93dd7f45c8d6bc66c36140470432bce7e06
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
- **Healthy**: Sufficient majority but not all nodes online
- **Degraded**: Reduced fault tolerance or missing key material
- **Unhealthy**: Insufficient nodes for operations or other failures

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

- `0`: Success (the health check completed and printed results)
- `1`: Error (tool execution failure, e.g. unreachable endpoint or invalid config file)

Note: the health status level (Optimal, Healthy, Degraded, Unhealthy) is reported in the output but does not affect the exit code.
The tool exits `0` as long as it can complete the check, regardless of the health status reported.
