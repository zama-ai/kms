# Zama KMS Core Helm Chart

A helm chart to distribute and deploy the [KMS](https://github.com/zama-ai/kms/).
It allows to run centralized (1 party) or threshold (multiple parties) networks.
The chart allows running either a single party or all parties in one release.

**This chart (1.6.3) and its `values.schema.json` are only for KMS v0.13.22.**
Do not install it against any other KMS version (including older 0.13.x or 0.14.x).

Chart 1.6.3 requires every values overlay to set
`kmsCore.thresholdMode.legacyPrssMask` (`beforePublicDecryptId` and
`beforeUserDecryptId`, quoted strings). Chart defaults do not provide this
block, so a bare `helm install` without `-f` fails schema validation. Use empty
strings for rolling-upgrade pass 1, then identical hex/decimal IDs once every
party runs v0.13.22.

## Installing the Chart

To pull and install the OCI Helm chart from ghcr.io:

    helm registry login ghcr.io/zama-ai/kms/charts
    helm install kms oci://ghcr.io/zama-ai/kms/charts/kms-core --version 1.6.3 -f values.yaml

To pull and install the OCI Helm chart from hub.zama.ai:

    helm registry login hub.zama.ai
    helm install kms oci://hub.zama.ai/zama-protocol/zama-ai/kms/charts/kms-core --version 1.6.3 -f values.yaml

The overlay must include:

    kmsCore:
      image:
        tag: v0.13.22
      thresholdMode:
        legacyPrssMask:
          beforePublicDecryptId: ""
          beforeUserDecryptId: ""

## Local testing

When `minio.enabled=true`, connect to minio UI on http://localhost:9001:

    kubectl port-forward svc/minio 9001

Interact with the bucket using the `aws` CLI:

    kubectl port-forward svc/minio 9000
    AWS_ACCESS_KEY_ID=kms-access-key-id AWS_SECRET_ACCESS_KEY=kms-secret-access-key aws --endpoint-url http://localhost:9000 --region eu-west-1 s3 ls s3://kms-public
