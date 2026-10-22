# Zama KMS Core Helm Chart

A helm chart to distribute and deploy the [KMS](https://github.com/zama-ai/kms/).
It allows to run centralized (1 party) or threshold (multiple parties) networks.
The chart allows running either a single party or all parties in one release.

## Installing the Chart

To pull and install the OCI Helm chart from ghcr.io:

    helm registry login ghcr.io/zama-ai/kms/charts
    helm install kms oci://ghcr.io/zama-ai/kms/charts/kms-core

To pull and install the OCI Helm chart from hub.zama.ai:

    helm registry login hub.zama.ai
    helm install kms oci://hub.zama.ai/zama-protocol/zama-ai/kms/charts/kms-core

## Public vault folder and TLS subject of a party

The TLS certificate and key of party `<id>` live in the public vault under one folder. The chart resolves it in this order:

1. The `prefix` of the party's `peersList` entry.
2. For this party only, `kmsCore.publicVault.s3.prefix`.
3. `PUB-p<id>`.

The same folder is used to upload this party's certificate, to fetch its key and CA at boot, and by clients and key generation. If this party's own `peersList` entry sets a `prefix`, it must equal `kmsCore.publicVault.s3.prefix` (when set): the core writes there, and peers read the entry.

`kmsPeers.name`, when set, is the TLS subject and the certificate name. It must equal the `host` of this party's `peersList` entry, because peers check the certificate against that host. The chart fails to render if they differ.

### Upgrading a deployment without an enclave

Before chart 1.8.6, the certificate and key were always stored under `PUB-p<id>`. Without an enclave, the job that creates them runs only on install, so an upgrade does not move them. If you set `kmsCore.publicVault.s3.prefix`, or a `prefix` on this party's `peersList` entry, to anything other than `PUB-p<id>`, copy the files before upgrading:

```sh
aws s3 cp --recursive s3://<public-bucket>/PUB-p<id>/CACert/ s3://<public-bucket>/<prefix>/CACert/
aws s3 cp --recursive s3://<public-bucket>/PUB-p<id>/PrivateKey/ s3://<public-bucket>/<prefix>/PrivateKey/
```

Peers that list this party must use the same `prefix`. With an enclave, the job also runs on upgrade when `kmsGenCertAndKeys.enabled` is set.

## Local testing

When `minio.enabled=true`, connect to minio UI on http://localhost:9001:

    kubectl port-forward svc/minio 9001

Interact with the bucket using the `aws` CLI:

    kubectl port-forward svc/minio 9000
    AWS_ACCESS_KEY_ID=kms-access-key-id AWS_SECRET_ACCESS_KEY=kms-secret-access-key aws --endpoint-url http://localhost:9000 --region eu-west-1 s3 ls s3://kms-public
