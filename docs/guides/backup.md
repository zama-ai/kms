# KMS backup CLI Tool

The tool allows to make custodian keys using a BIP39 seed phrase and help operators in recovery of backups (through reencryption) by using a seed pharase.

## Prerequisites

- [Rust](https://www.rust-lang.org/tools/install). Ensure you have a recent version of Rust installed on your system. We require `v1.86` or newer.

## Usage

WARNING: This tool is only mean to be used in a highly secure setting. This means that a lot of steps must be taken to ensure security. More specifically an _air gapped_ system *must* be used.
In particular, for all usages, the following steps must be taken:
1. Construct a trusted live version of an operating system.
2. Boot this live OS on a factory new machine.
3. On a separate machine prepare necessary installation files: I.e. either Rust and the source code of this repository, or a trusted pre-compiled binary of the backup utility. 
4. These must then be copied to a factory-fresh USB stick.

### Custodian setup

Run the CLI tool with the `generate` command in order to generate keys for a custodian. More specifically:
```{bash}
$ cargo run --bin kms-custodian generate --randomness <random string of chars> --custodian-role <1-index role> --custodian-name <name of the custodian as a string> --path <path and name of the file where the custodian setup info should stored>
```
Observe that the `randomness` supplied is used along with entropy of the current system to derive keys, and thus the command is *not* idempotent. 
This will generate a fresh pair of keys for the given custodian and store this along with relevant meta-data in the directory pointed to by the path.
Furthermore, this will print a BIP39 seed phrase on the screen. This seed phrase must be copied _exactly_ on to a piece of paper. The paper should be stored securely as this is needed in order to perform recovery.

Observe the seed phrase and the private keys do not get logged or saved to disc; only printed _once_ to stdout. 

For example the command may look like this:
```{bash}
$ cargo run --bin kms-custodian generate --randomness 123 --custodian-role 3 --custodian-name homer-3 --path  core-client/tests/data/keys/CUSTODIAN/setup-msg/setup-3
```

### Key verification 

Run the CLI tool with the `verify` command in order to validate that a seed phrase is the one used to generate certain setup information. More specifically:
```{bash}
$ cargo run --bin kms-custodian verify --seed-phrase <the seed phrased used for generation> --path <path and name of the file where the custodian setup info should stored>
```
The call will print any inconsistencies found between the public keys generated from the seed phrase and those in the data supplied.

For example:
```{bash}
$ cargo run --bin kms-custodian verify --seed-phrase "stick essence exhaust bunker meat orchard wolf timber tackle gesture video cheap" --path core-client/tests/data/keys/CUSTODIAN/setup-msg/setup-3
```

### Recovery (decryption of backup)

Run the CLI tool with the `decrypt` command in order to decrypt a backup, and then reencrypt it under a supplied operator keyset. More specifically:
```bash
$ kms-backup decrypt --seed-phrase <the seed phrased used for generation> --randomness <random string of chars> --custodian-role <1-index role> --recovery-request-path <path and name of the file where the operator recovery request reside> --output-path <path and name of the file where the result of the reencryption should be stored>
```
Observe that the `randomness` supplied is used along with entropy of the current system to do re-encryption, and thus the command is *not* idempotent. 

IMPORTANT: IT IS NOT POSSIBLE FOR THE CUSTODIAN TO VALIDATE THE AUTHENTICITY OF A REQUEST! HENCE IT IS PARAMOUNT THAT IT IS VALIDATED OUT-OF-BOUNDS, E.G. THROUGH A DIGEST ON A BLOCKCHAIN.
Run the CLI tool with the `decrypt` command in order decrypt a backup, and then reencrypt it under a supplied operator keyset. More specifically:
```{bash}
$ cargo run --bin kms-custodian decrypt--seed-phrase <the seed phrased used for generation> --randomness <random string of chars> --custodian-role <1-indexed role of the custodian> --recovery-request-path <path to the recovery information given by the operator from custodian-recovery-init> --operator-verf-key <the path to the verification key of the KMS operator> --output-path <path to store the custodian's output to the specific operator whose recovery info was given>
```
Observe that the `randomness` supplied is used along with entropy of the current system to do re-encryption, and thus the command is *not* idempotent. 

For example:
```{bash}
$ cargo run --bin kms-custodian decrypt --seed-phrase "stick essence exhaust bunker meat orchard wolf timber tackle gesture video cheap" --randomness 123  --custodian-role 1 --recovery-request-path core-client/tests/data/keys/CUSTODIAN/recovery/1 --operator-verf-key core-client/tests/data/keys/PUB-p1/VerfKey/60b7070add74be3827160aa635fb255eeeeb88586c4debf7ab1134ddceb4beee --output-path core-client/tests/data/keys/CUSTODIAN/response/recovery-response-1-1
```

IMPORTANT: IT IS NOT POSSIBLE FOR THE CUSTODIAN TO VALIDATE THE AUTHENTICITY OF A REQUEST! HENCE IT IS PARAMOUNT THAT IT IS VALIDATED OUT-OF-BOUNDS, E.G. THROUGH A DIGEST ON A BLOCKCHAIN.
