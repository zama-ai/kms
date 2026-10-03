# Upgrade from v0.14 to v0.15

An upgrade from v0.14.x to v0.15.x has two tasks:

- A threshold party must supply an epoch-data migration config. Without it, the v0.15 core does not start. The sections from [Who needs the migration config](#who-needs-the-migration-config) to [Error messages](#error-messages) describe this task.
- Each node must generate a root signing seed. Without it, the node signs only under ECDSA. See [Generate the root signing seed](#generate-the-root-signing-seed).

## Who needs the migration config

You need the migration config if both of these conditions are true:

- Your party runs in threshold mode. A centralized KMS does not migrate PRSS data.
- Your party ran `kms-init` or another new-MPC-epoch request on v0.14, so its private storage holds PRSS data.

A fresh v0.15 installation has no legacy PRSS data. Do not set the migration config on a fresh installation. The core checks that each epoch in the config has PRSS data in storage, so on a fresh installation it stops at startup (see [Error messages](#error-messages)).

## What the core does at startup

v0.14 stores one PRSS setup per epoch in private storage, under the `PrssSetupCombined` data type. The stored setup does not record the MPC context that the epoch belongs to.

v0.15 stores epochs as `EpochData` entries, and each entry records its context. At startup, the core reads each legacy PRSS setup and writes it again as an `EpochData` entry. The migration config supplies the context for each epoch. The core finds the legacy PRSS data without help, but it cannot find the context of an epoch, because the legacy data does not record it.

The migration is idempotent: the core skips each epoch that already has an `EpochData` entry, so a restart with the same config is safe. The legacy PRSS data stays in storage for all v0.15.x releases. At each startup, the core compares the config with the legacy PRSS data again. Thus the config must stay in place, unchanged, while the party runs v0.15.x.

## Find the epochs to list

The config must list each epoch that has PRSS data in private storage, and no other epochs. The epoch IDs are the object names under the `PrssSetupCombined` data type in the private vault of the party:

- S3 storage: `s3://<private-bucket>/<private-prefix>/PrssSetupCombined/<epoch-id>`
- File storage: `<private-path>/<private-prefix>/PrssSetupCombined/<epoch-id>`

`<private-bucket>`, `<private-path>` and `<private-prefix>` are the `bucket`, `path` and `prefix` values of the private vault in the core config (`[private_vault.storage.s3]` or `[private_vault.storage.file]`). With the Helm chart, the bucket and the prefix are `kmsCore.privateVault.s3.bucket` and `kmsCore.privateVault.s3.prefix`. If the prefix is not set, the core uses `PRIV`.

For example, for party 1 with the bucket `kms-private` and the prefix `PRIV-p1`, list the epochs with the AWS CLI:

```bash
aws s3 ls "s3://kms-private/PRIV-p1/PrssSetupCombined/"
```

The output has one entry per epoch. The name of the entry is the epoch ID, for example `0800000000000000000000000000000000000000000000000000000000000001` (the default epoch ID without the `0x` prefix).

Each epoch belongs to the context that the new-MPC-epoch request used when it created the epoch. `kms-init` creates the first epoch with these default IDs:

- Default context ID: `0x0700000000000000000000000000000000000000000000000000000000000001`
- Default epoch ID: `0x0800000000000000000000000000000000000000000000000000000000000001`

Most parties have only this epoch. If you created more epochs, for example through resharing, list each of them under the context that its request used.

## Write the migration config

The config is a list of contexts. Each context lists the epochs that belong to it. These rules apply:

- The config must contain the default context, and the default context must contain the default epoch.
- An epoch ID must occur under one context only.
- A context ID must occur one time only, and each context must list at least one epoch.
- IDs are hex strings. The `0x` prefix is optional.

With the Helm chart, set `kmsCore.migration.contextAssociations`. Use chart version 1.9.x or later, because earlier charts do not have this value.

```yaml
kmsCore:
  migration:
    contextAssociations:
      - contextId: "0x0700000000000000000000000000000000000000000000000000000000000001"
        epochIds:
          - "0x0800000000000000000000000000000000000000000000000000000000000001"
```

Without Helm, add the `[[migration.context_associations]]` section to the core config file:

```toml
[[migration.context_associations]]
context_id = "0x0700000000000000000000000000000000000000000000000000000000000001"
epoch_ids = ["0x0800000000000000000000000000000000000000000000000000000000000001"]
```

## Rolling upgrades

A v0.14 core rejects the `[migration]` section as an unknown field. During a rolling upgrade, set the migration config only on the parties that run v0.15.

Each Helm upgrade can restart the core, and each restart runs the migration check again. Thus include the migration config in each Helm upgrade of an upgraded party, also in later upgrade batches.

## After the upgrade

The migration config exists only in v0.15.x. Remove it when you upgrade to v0.16.

## Error messages

The core stops at startup with one of these errors if the migration config is missing or does not match the stored data.

| Error | Cause and fix |
| --- | --- |
| `Migration config must be provided for 0.15.x migration when PRSS data is present` | Private storage holds legacy PRSS data, and the config has no migration section. Add the migration config. |
| `Migration config does not cover N stored epoch(s) with PRSS data: ...` | The config does not list all stored epochs. Add the listed epochs. |
| `Migration config references N epoch(s) that have no PRSS data on disk: ...` | The config lists epochs that are not in private storage. Remove the listed epochs. On a fresh installation, remove the complete migration config. |
| `Default context ID ... should be part of the migration config` | The config does not contain the default context. Add it. |
| `Default epoch ID ... should be part of the migration config for default context ID ...` | The default context does not list the default epoch. Add it. |
| `Duplicate epoch ID ... found in migration config` or `Duplicate context ID ... found in migration config` | An ID occurs more than one time. Remove the duplicate. |

## Generate the root signing seed

v0.15 adds post-quantum signature schemes. The node derives the signing keys of these schemes from a root signing seed. The seed is stored in private storage, under the `SigningSeed` data type. A v0.14 node has only the ECDSA signing key, so each node must generate a seed one time.

A node without a seed starts, but it signs only under ECDSA. A request for a different scheme fails. At startup, the core logs this warning:

```text
No root signing seed found in storage "..."; this node can only sign under ECDSA. Run kms-gen-keys to generate one.
```

### Who must do this step

- Centralized and threshold nodes must both do this step.
- With the Helm chart, a node without an enclave runs `kms-gen-keys` at each pod start. That run generates the seed after the upgrade, so you only do the check in [Check the result](#check-the-result).
- An enclave node does not generate the seed at boot. At a normal boot, the enclave receives the `kms-server` config, and `kms-gen-keys` rejects that config. The Helm chart sends the `kms-gen-keys` config to the enclave only in the `pre-install` job. Thus you must run `kms-gen-keys` with the `kms-gen-keys` config of the node.
- A node without Helm must run `kms-gen-keys`.

### Run kms-gen-keys

Run `kms-gen-keys` with the `kms-gen-keys` config that you used to install the node. The config must point to the public and private vaults of the node.

```bash
kms-gen-keys --config-file kms-gen-keys.toml
```

The run keeps the ECDSA signing key of the node, so the registered ECDSA address does not change. The run adds the seed and the verification material of each scheme to the vaults. Expect these log messages:

- `Signing keys already exist, skipping generation`. This message is about the ECDSA key.
- `Generated a root signing seed under the handle ...`.

Do not set these options in the `[keygen]` section:

- `overwrite`: this option deletes the ECDSA signing key and generates a new identity. The node then has an ECDSA address that nobody registered.
- `repopulate`: this option requires an existing seed, so it fails on a v0.14 node.

A second run is safe, because the run uses the stored seed again.

### Check the result

Add `show_existing = true` to the `[keygen]` section, and run `kms-gen-keys` again. Make sure that:

- The output contains a `SigningSeed` line.
- The output contains one `TypedVerfAddress` line for each signature scheme.
- The ECDSA address did not change.

### Seed error

If `kms-gen-keys` stops with `public storage already holds non-ECDSA verification material, but the SigningSeed object ... is missing`, public storage holds post-quantum verification material but private storage has no seed. This occurs, for example, when you restore private storage from an old backup. Restore the seed from the backup vault. Do not generate a new seed, because a new seed changes each published post-quantum identity.

For more information about `kms-gen-keys`, see [KMS Core Service Binaries](../guides/kms-server-bin.md#kms-key-generation).
