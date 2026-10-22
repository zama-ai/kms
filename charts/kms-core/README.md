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

## Booting a threshold party without a peer list

By default, the chart renders `[[threshold.peers]]` into the `kms-server` config. The server turns this list into the default MPC context and rewrites that context in private storage on every boot.

With `kmsCore.thresholdMode.omitPeers: true`, the chart renders no peer list and skips its `3*t+1` party check. The server then writes no default context: it loads only the MPC contexts already in its private storage. The init script still fetches this party's own TLS certificate and key.

### Where the committee comes from

MPC contexts (`ContextInfo`) live in the private vault of the party. They are written when the core handles a `NewMpcContext` request. In production, the KMS connector sends this request when the `ProtocolConfig` contract emits `NewKmsContext`, with the node list and PCR values set by governance. A context written by an earlier boot with a peer list stays in storage too.

At boot, the server verifies each stored context and skips any that fails:

- The node list contains this party's signing key.
- Party IDs are unique and in `1..n`, and `n = 3t+1`.
- Node names and verification keys are unique.
- In enclave deployments, the context carries PCR values.

### When to use it

- A party deployed on its own (`kmsPeers.count: 1`) whose committee is defined on chain, for example a new or replacement operator that joins through a context switch. A generated peer list would describe a one-party committee.
- A party whose committee changed after its values were written. A peer list would rewrite the default context with stale data on every boot.

### When not to use it

- The first deployment of a new committee, before any context exists. The party has no context and cannot serve MPC requests until it receives a `NewMpcContext` that includes it. Bootstrap with `peersList`.
- When you need to change the default context from values. With `omitPeers`, the stored default context is no longer updated.
- When the core gRPC port (`kmsCore.ports.client`, 50100 by default) is reachable by anything other than the KMS connector. `NewMpcContext` is not authenticated, and the checks above verify the shape of a context, not that governance approved it.

### Why it is safe

- The committee comes from private storage, not from a value the host supplies on each boot. In enclave deployments, the private vault is encrypted by its AWS KMS keychain, and the enclave does not measure its config. Omitting the peer list removes one input that the host controls.
- Every stored context is verified at boot, and in enclave deployments it must carry the PCR values that peers' attestation is checked against.
- New contexts follow the same path as any context switch: from `ProtocolConfig`, through the connector.

### Why a flag and not an empty `peersList`

An empty `peersList` already means "generate peers `1..kmsPeers.count`", which releases that run every party rely on. Reading an empty list as "no peer list" would silently change those deployments. `omitPeers` states the intent, and it renders the same server config as `kms-server --ignore-peerlist`.

## Local testing

When `minio.enabled=true`, connect to minio UI on http://localhost:9001:

    kubectl port-forward svc/minio 9001

Interact with the bucket using the `aws` CLI:

    kubectl port-forward svc/minio 9000
    AWS_ACCESS_KEY_ID=kms-access-key-id AWS_SECRET_ACCESS_KEY=kms-secret-access-key aws --endpoint-url http://localhost:9000 --region eu-west-1 s3 ls s3://kms-public
