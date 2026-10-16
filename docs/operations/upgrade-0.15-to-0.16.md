# Upgrade from v0.15 to v0.16

Version 0.16 removes the KMS rate limiter. Remove the entire `[rate_limiter_conf]` section from every centralized and threshold KMS configuration file.

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
