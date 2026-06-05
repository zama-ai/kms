# KMS Testing in Kind

This directory contains the configuration consumed by the KMS deployment
scripts in [`ci/scripts/`](../scripts/) when testing KMS in a local Kubernetes
cluster using [Kind (Kubernetes in Docker)](https://kind.sigs.k8s.io/).

The deployment workflow itself (local usage, CI usage, options,
troubleshooting) is documented in [`ci/scripts/README.md`](../scripts/README.md).

## Quick start

```bash
# From the repository root
./ci/scripts/deploy.sh --target kind-local
```

In CI, the lifecycle is managed by `ci/scripts/manage_lifecycle.sh start` /
`stop` — see [`.github/workflows/kind-testing.yml`](../../.github/workflows/kind-testing.yml).

## Directory contents

### `infra/`

- `kind-config.yaml` — Kind cluster definition (control-plane and worker nodes)
- `localstack-s3-values.yaml` — Helm values for Localstack, which provides
  S3-compatible object storage inside the cluster

### `kms/`

Helm values used by the deployment scripts:

**Default values (used by CI):**

- `values-kms-test.yaml` — base configuration for KMS Core
- `values-kms-service-init-kms-test.yaml` — initialization job and KMS Core
  Client configuration
- `values-kms-service-gen-keys-kms-test.yaml` — key generation job
  configuration

**Local values (auto-generated, Git-ignored):**

- `local-values-*.yaml` — local overrides created by the deployment scripts
  for local runs; safe to delete, recreated on the next run

The `<namespace>` placeholders in the values files are replaced automatically
by the deployment scripts.

**Resource configuration:** look for the sections marked
`#==========RESOURCES TO ADJUST BASED ON ENVIRONMENT==========` in the values
files to adjust memory/CPU for your machine.
