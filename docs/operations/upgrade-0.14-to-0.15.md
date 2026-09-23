# Upgrade from v0.14 to v0.15: epoch-data migration

A threshold party that upgrades from v0.14.x to v0.15.x must supply a migration config. Without it, the v0.15 core does not start.

## Who needs the migration config

You need the migration config if both of these conditions are true:

- Your party runs in threshold mode. A centralized KMS does not migrate PRSS data.
- Your party ran `kms-init` or another new-MPC-epoch request on v0.14, so its private storage holds PRSS data.

A fresh v0.15 installation has no legacy PRSS data. Do not set the migration config on a fresh installation, because the migration then fails (see [Error messages](#error-messages)).

## What the core does at startup

v0.14 stores one PRSS setup per epoch in private storage, under the `PrssSetupCombined` data type. The stored setup does not record the MPC context that the epoch belongs to.

v0.15 stores epochs as `EpochData` entries, and each entry records its context. At startup, the core reads each legacy PRSS setup and writes it again as an `EpochData` entry. The migration config supplies the context for each epoch.

The migration is idempotent. The core skips each epoch that already has an `EpochData` entry. The legacy PRSS data stays in storage for all v0.15.x releases, and the core checks it at each startup. Thus the config must stay in place while the party runs v0.15.x.

## Find the epochs to list

The config must list each epoch that has PRSS data in private storage, and no other epochs. The epoch IDs are the object names under the `PrssSetupCombined` data type in the private vault of the party:

- S3 storage: `s3://<private-bucket>/<private-prefix>/PrssSetupCombined/<epoch-id>`
- File storage: `<private-path>/<private-prefix>/PrssSetupCombined/<epoch-id>`

For example, with the AWS CLI:

```bash
aws s3 ls "s3://<private-bucket>/<private-prefix>/PrssSetupCombined/"
```

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

Each Helm upgrade can restart the core, and each restart runs the migration check again. Thus include the migration config in each Helm upgrade of an upgraded party, also in later upgrade waves.

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
