# Project specific lints for KMS

This tool is based on [Dylint](https://github.com/trailofbits/dylint).

## Usage

From the KMS repository root:

```sh
cargo dylint --all --workspace
```

Do not pass `--all-targets` when generating the inventory, because the lint is
intended to describe production lib/bin targets, not tests, benches, or
examples.

## Lints

### `bc2wrap_type_inventory`

Collects the root workspace-local types used at curated serialization sink call
sites, including:

- `bc2wrap::serialize`
- `bc2wrap::serialize_into`
- `bc2wrap::deserialize_safe`
- `bc2wrap::deserialize_unsafe`
- `store_versioned_at_request_id`
- `store_versioned_at_request_and_epoch_id`
- `read_versioned_at_request_id`
- `read_versioned_at_request_and_epoch_id`
- the `write_all` storage wrapper method

The lint writes one JSON file per checked crate target under
`target/kms-lints/bc2wrap-type-inventory` by default. Set
`KMS_BC2WRAP_INVENTORY_DIR` to override the output directory.

The inventory records only root types. It does not recursively expand fields.
Each file contains full `calls` plus a `types` summary categorized as `local`,
`foreign`, `generic`, `compound`, `primitive`, or `unknown` for auditability.
Call records include `sink_path` (the rustc def path of the matched sink),
and type summaries aggregate every distinct sink path each root flowed through.
