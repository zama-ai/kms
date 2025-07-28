# On-Premises Installation Guide

This guide explains how to set up and deploy the KMS service using Helm charts in an on-premises environment.
And also locally for testing purposes

## Prerequisites

### System Requirements
- Kubernetes cluster (version 1.19 or later)
- Bucket: AWS S3 or GCS for cloud deployment. Minio can be enable for local kubernetes deployment
- [Helm](https://helm.sh/) (version 3.8 or later)
- `kubectl` CLI tool configured to access your cluster [https://kubernetes.io/docs/reference/kubectl/](https://kubernetes.io/docs/reference/kubectl/)
- [Kyverno](https://kyverno.io/) setup in your cluster and enable
- Access to container registry (for pulling KMS service images)

### Required Storage
- Minimum 5GB storage per KMS core instance

## Installation Steps

## 1. Prepare bucket and configmap

At Zama, we use crossplane to depoy infrastructure parts (buckets and configmaps) in the cluster.

For the public storage and the private storage, you can use AWS S3 or GCS.
And you can use local storage for private storage for keys on each party.


For the public storage, you have to create:
- one bucket
- one IRSA (IAM Roles for Service Accounts).
- one service account with IRSA annotations.

If you decide to use private bucket storage bucket, you have to set more configuration before.
On AWS, you have to create for each party:
- one private bucket.
- one configmap for each party containing the private bucket name. The name will have to follow the name of the pod generated. (ie: name: kms-threshold-staging-1).
- one IRSA (IAM Roles for Service Accounts).
- one service account with IRSA annotations.

This way, the pod with the attached service account would be able to access the private bucket.

Example of one configmap for one party for public and private buckets:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: kms-threshold-staging-1
  namespace: kms-threshold-staging
data:
  CORE_CLIENT__S3_ENDPOINT: https://zama-public-bucket.s3.eu-west-1.amazonaws.com
  KMS_CORE__PRIVATE_VAULT__STORAGE__S3__BUCKET: zama-private-bucket
  KMS_CORE__PUBLIC_VAULT__STORAGE__S3__BUCKET: zama-public-bucket
```

Example of a service account for one party:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: kms-threshold-staging-1
  namespace: kms-threshold-staging
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::<account_id>:role/<role-name>
```

And you also need Kyverno setup in your cluster and enable in your values.
A policy will be deployed at startup.
Kyverno allows pod admission controller to mutate pods based on policy.
It ensures that the pods are running with the desired configuration.
More information [here](https://kyverno.io/docs/getting-started/)


### 2. Prepare the Values File

Create a custom values file (e.g., `my-values.yaml`) to override the default configuration. Here's a minimal example:

```yaml
kmsPeers:
  # Number of replicas managed by each statefulset
  count: 4

kmsConnector:
  enabled: false

kmsCore:
  nameOverride: kms-threshold-staging
  addressOverride:
  image:
    name: ghcr.io/zama-ai/kms-service
    tag: latest
  thresholdMode:
    enabled: true
    initializationScript:
      enabled: true
    peersList:
      - id: 1
        host: kms-threshold-staging-1
        port: 50001
      - id: 2
        host: kms-threshold-staging-2
        port: 50001
      - id: 3
        host: kms-threshold-staging-3
        port: 50001
      - id: 4
        host: kms-threshold-staging-4
        port: 50001
  aws:
    region: eu-west-1
  publicVault:
    s3:
      enabled: true
      bucket: "your-public-bucket"
      path: ""
  storage:
    storageClassName: gp3
    capacity: 5Gi
  resources:
    requests:
      memory: 12Gi
      cpu: 2
    limits:
      memory: 24Gi
      ephemeralStorage: 1Gi


kyverno:
  enabled: false
```

### 3. Install the Chart

If you clone the kms-core repository, you can use the command below to install the chart with the values-example-local.yaml file.
To install the chart in your cluster, run the command below from your machine.
Be sure to target the cluster and the right context.

```bash
# From the kms-core directory
helm install kms-core ./charts/kms-core -f ./charts/kms-core/values-example-local.yaml -n kms-threshold-staging
```

If you want to use the chart from the registry you can log into ghcr.io and run the following with the **version** you want:

```bash
helm upgrade --install kms-core oci://ghcr.io/zama-ai/kms/helm-charts/kms-service --version <version> -f ./charts/kms-core/values-example-local.yaml -n kms-threshold-staging --create-namespace --dependency-update
```


## Configuration Options

### Threshold Mode

To enable threshold mode, add the following to your values file:

```yaml
kmsCore:
  thresholdMode:
    enabled: true
    # Number of peers (must match kmsPeers.count)
    dec_capacity: 10000
    min_dec_cache: 6000
    num_sessions_preproc: 2 # Number of core of vCPU

kmsPeers:
  count: 4  # Number of KMS peers for threshold setup
```

### Centralized Mode

To enable centralized mode, add the following to your values file:

```yaml
kmsCore:
  thresholdMode:
    enabled: false

kmsPeers:
  count: 1  # For centralized setup keep 1 peer
```

### Storage Configuration

The KMS service requires persistent storage for its operation. Configure it according to your environment:
You can keep empty to use the default storage class or set the default storage class name in the values file.
In AWS for example it can be `gp2` or `gp3`.

```yaml
kmsCore:
  storage:
    storageClassName: <storage-class>  # Your storage class
    capacity: 5Gi  # Adjust based on your needs
```

### Security Context

The KMS service runs with specific security contexts that should be maintained:
It avoids privilege escalation and file system access issues.

```yaml
podSecurityContext:
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop:
      - ALL
  privileged: false
```

### Resource Requirements

The KMS service requires sufficient CPU and memory resources to handle key generation and encryption operations efficiently. Here are the recommended resource configurations:

```yaml
kmsCore:
  resources:
    requests:
      cpu: "2"        # Minimum 2 CPU cores
      memory: "4Gi"   # Minimum 4GB RAM for base operations
    limits:
      cpu: "4"        # Maximum 4 CPU cores
      memory: "8Gi"   # Maximum 8GB RAM to handle peak loads

  # For threshold mode, increase resources:
  thresholdMode:
    resources:
      requests:
        cpu: "4"      # Minimum 4 CPU cores for threshold operations
        memory: "8Gi" # Minimum 8GB RAM for threshold operations
      limits:
        cpu: "8"      # Maximum 8 CPU cores
        memory: "16Gi" # Maximum 16GB RAM for complex key generation
```

### 3. Install the Chart locally with minio

To install the chart locally with minio, use the value files below.
Be sure to target the cluster and the right context.
For a local cluster development, you can use docker desktop, Kind or minikube.

```yaml
kmsPeers:
  # Number of replicas managed by each statefulset
  count: 4

kmsConnector:
  enabled: false

kmsCoreClient:
  enabled: false

kmsCore:
  nameOverride: kms-threshold-staging
  addressOverride:
  image:
    name: ghcr.io/zama-ai/kms-service
    tag: latest
  thresholdMode:
    enabled: true
    initializationScript:
      enabled: true
    peersList:
      - id: 1
        host: kms-threshold-staging-1
        port: 50001
      - id: 2
        host: kms-threshold-staging-2
        port: 50001
      - id: 3
        host: kms-threshold-staging-3
        port: 50001
      - id: 4
        host: kms-threshold-staging-4
        port: 50001
  aws:
    region: eu-west-1
  storage:
    capacity: 5Gi
  serviceMonitor:
    enabled: false
  resources:
    requests:
      memory: 2Gi
      cpu: 2
    limits:
      memory: 4Gi
      ephemeralStorage: 1Gi

environment: dev

rustLog: info

minio:
  enabled: true

kyverno:
  enabled: false
```

> **Important**: These resource limits are crucial to prevent Out-Of-Memory (OOM) kills during key generation operations. If you experience OOM issues, consider increasing the memory limits based on your workload.

Factors affecting resource requirements:
- Number of concurrent key generation requests
- Key size and complexity
- Threshold mode configuration
- Number of active sessions

For production deployments with heavy workloads, monitor resource usage and adjust accordingly. It's recommended to start with higher limits and adjust down based on observed usage patterns.

## Post-Installation Verification

1. Check if all pods are running:
   ```bash
   kubectl get pods -n <namespace>
   ```

2. Verify the services are exposed:
   ```bash
   kubectl get svc -n <namespace>
   ```

3. Check the logs for any errors:
   ```bash
   kubectl logs -f deployment/kms-service -n <namespace>
   ```

## Troubleshooting

### Common Issues

1. **Storage Issues**
   - Ensure your storage class exists and supports the required access modes
   - Check PVC status: `kubectl get pvc -n <namespace>`

2. **Image Pull Errors**
   - Verify container registry access
   - Check image name and tag in values file

3. **Pod Startup Issues**
   - Check pod events: `kubectl describe pod <pod-name> -n <namespace>`
   - Verify resource requirements are met

## Maintenance

### Upgrading

To upgrade the KMS service:

```bash
helm upgrade kms-service ./charts/kms-service -f my-values.yaml -n <namespace>
```

### Uninstalling

To remove the KMS service:

```bash
helm uninstall kms-service -n <namespace>
```

Note: This will not delete PVCs by default. To delete them:
```bash
kubectl delete pvc -l app.kubernetes.io/instance=kms-service -n <namespace>
```
