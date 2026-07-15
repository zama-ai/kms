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

### Why default to `imagePullPolicy: Always` for the sidecar images?

The sidecar containers in this chart use [Chainguard](https://www.chainguard.dev/) base images.
Chainguard images are continuously rebuilt to include the latest security patches. Importantly, these rebuilds are published under the **same tag** — the tag name stays constant, but the image it points to is updated over time (a "mutable" tag). This means a given tag today may contain newer patches than the same tag did last week.
To benefit from these patches, we set `imagePullPolicy: Always` on the sidecars. This tells the kubelet to re-check the registry every time a sidecar container starts. As a result, whenever a pod restarts, it automatically pulls the most recently patched image — with no need to modify this chart or bump a version.
If we used `IfNotPresent` instead, a node would keep running whatever image it had already cached and would silently miss all subsequent security patches.

A couple of things worth noting:
- **This is cheap.** If the image hasn't actually changed since the last pull, nothing is re-downloaded — the kubelet only verifies the current image against the registry and reuses the cached layers.
- **The only trade-off** is that the registry must be reachable when a sidecar container starts. Already-running pods are never affected; the check happens only at container start (restart, reschedule, or node scale-up).

## Local testing

When `minio.enabled=true`, connect to minio UI on http://localhost:9001:

    kubectl port-forward svc/minio 9001

Interact with the bucket using the `aws` CLI:

    kubectl port-forward svc/minio 9000
    AWS_ACCESS_KEY_ID=kms-access-key-id AWS_SECRET_ACCESS_KEY=kms-secret-access-key aws --endpoint-url http://localhost:9000 --region eu-west-1 s3 ls s3://kms-public
