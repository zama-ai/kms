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

### `versioned_codec_inventory`

Collects the root workspace-local types used at TFHE safe-serialization
encode/decode sink call sites in checked local MIR, including:

- `tfhe_safe_serialize::safe_serialize`
- `tfhe_safe_serialize::safe_deserialize`
- `tfhe_safe_serialize::safe_deserialize_conformant`

The lint writes one JSON file per checked crate target under
`target/kms-lints/versioned-codec-inventory` by default. Set
`KMS_VERSIONED_CODEC_INVENTORY_DIR` to override the output directory.

The inventory records only root types. It does not recursively expand fields.
Each file contains full `calls` plus a `types` summary categorized as `local`,
`foreign`, `generic`, `compound`, `primitive`, or `unknown` for auditability.
Call records include `sink_path` (the rustc def path of the matched sink),
and type summaries aggregate every distinct sink path each root flowed through.
Storage wrapper and trait functions are intentionally not listed as sinks; a
storage-backed value is recorded only when the scanner reaches the concrete
TFHE safe-serialization encode/decode call.
