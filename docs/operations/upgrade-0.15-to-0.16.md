# Upgrade from v0.15 to v0.16

## Rate limiter

Version 0.16 removes the KMS rate limiter. Remove the entire `[rate_limiter_conf]` section from every KMS configuration file.

This includes all seven settings, regardless of their configured values:

| Setting | Former purpose |
| --- | --- |
| `rate_limiter_conf.bucket_size` | Set the total number of available tokens. |
| `rate_limiter_conf.pub_decrypt` | Set the token cost of public decryption. |
| `rate_limiter_conf.user_decrypt` | Set the token cost of user decryption. |
| `rate_limiter_conf.crsgen` | Set the token cost of CRS generation. |
| `rate_limiter_conf.preproc` | Set the token cost of key generation preprocessing. |
| `rate_limiter_conf.keygen` | Set the token cost of key generation. |
| `rate_limiter_conf.new_epoch` | Set the token cost of MPC epoch creation. |

For example, remove this whole block from a TOML configuration:

```toml
[rate_limiter_conf]
bucket_size = 50000
pub_decrypt = 1
user_decrypt = 1
crsgen = 100
preproc = 25000
keygen = 1000
new_epoch = 1
```

Also remove any corresponding environment overrides:

```text
KMS_CORE__RATE_LIMITER_CONF__BUCKET_SIZE
KMS_CORE__RATE_LIMITER_CONF__PUB_DECRYPT
KMS_CORE__RATE_LIMITER_CONF__USER_DECRYPT
KMS_CORE__RATE_LIMITER_CONF__CRSGEN
KMS_CORE__RATE_LIMITER_CONF__PREPROC
KMS_CORE__RATE_LIMITER_CONF__KEYGEN
KMS_CORE__RATE_LIMITER_CONF__NEW_EPOCH
```

For Helm deployments, remove `kmsCore.rateLimiter.bucketSize` and its parent `kmsCore.rateLimiter` block from custom values files. Remove corresponding `--set` overrides from deployment commands.

These settings have no replacement. The decryption MetaStore limits, `[threshold].dec_capacity` and `[threshold].min_dec_cache`, remain valid and still control admission and result retention.

## Centralized mode

Version 0.16 removes the centralized KMS mode. Every node runs as a party of a threshold network.

### Server configuration

`kms-server` and `kms-gen-keys` require a `[threshold]` section. A configuration file without it fails at load with `missing configuration field "threshold"`. `kms-server` also reports `failed to load kms-server config file <path>; expected [service] and [threshold] sections`.

### Helm chart

The chart deploys threshold networks only. Rendering fails if `kmsCore.thresholdMode.enabled` is `false`.

The chart defaults changed:

| Setting | Old default | New default |
| --- | --- | --- |
| `kmsPeers.count` | `1` | `4` |
| `kmsCore.thresholdMode.thresholdValue` | `4` | `1` |

The new defaults describe one release that runs all 4 parties. If your release relies on the old defaults, set `kmsPeers.count: 1` and `kmsCore.thresholdMode.thresholdValue: 4` explicitly. Rendering fails if the number of parties is not `3 * thresholdValue + 1`.

### core-client configuration

The `kms_type` key is optional. The only accepted value is `"threshold"`. Any other value fails to load.

### Private storage and backups

A node does not boot if its private storage holds `FhePrivateKey` entries. The boot-time checks report them with the error `Foreign material in private storage`. A backup restore skips `FhePrivateKey` entries in the backup vault and logs a warning.

### Health checks

The proto `NodeType` value `1` is reserved. `kms-health-check` reports every node type other than `2` (`NODE_TYPE_THRESHOLD`) as `Unsupported node type <n>`, and it sets the overall status to Unhealthy.
