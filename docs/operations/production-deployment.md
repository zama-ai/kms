# KMS Party Production Deployment Guide

**Deploy your party's KMS node for a 13-party threshold network.**

## Overview

This guide covers production deployment of **your party's KMS node** in a **13-party threshold network**:

- **Infrastructure**: [Terraform MPC modules](https://github.com/zama-ai/terraform-mpc-modules) for your AWS EKS, S3, IAM, Nitro Enclaves
- **Application**: Official KMS Helm charts (`charts/kms-core/`) for your StatefulSet deployment  
- **Security**: AWS Nitro Enclaves, IRSA, PrivateLink networking to other parties
- **Architecture**: Your independent node in a decentralized 13-party threshold network

## Architecture

### 13-Party Network Topology
```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          13-Party Threshold Network                         │
│                              (t=4, n=13)                                   │
├──────────┬──────────┬──────────┬──────────┬──────────┬──────────┬──────────┤
│ Party 1  │ Party 2  │ Party 3  │ Party 4  │ Party 5  │   ...    │ Party 13 │
│ AWS Acc1 │ AWS Acc2 │ AWS Acc3 │ AWS Acc4 │ AWS Acc5 │          │ AWS Acc13│
├──────────┼──────────┼──────────┼──────────┼──────────┼──────────┼──────────┤
│    🏢     │    🏢     │    🏢     │    🏢     │    🏢     │    🏢     │    🏢     │
│  YOUR    │  Other   │  Other   │  Other   │  Other   │  Other   │  Other   │
│  PARTY   │  Party   │  Party   │  Party   │  Party   │  Party   │  Party   │
└──────────┴──────────┴──────────┴──────────┴──────────┴──────────┴──────────┘
     ▲                                                                    
     │◄──────────── PrivateLink Connections ──────────────────────────────┤
     └─────────────── To All Other 12 Parties ──────────────────────────┘
```

### Your Party's Components
You deploy and manage:
- **1 EKS Cluster** with Nitro Enclaves-enabled nodes
- **1 KMS StatefulSet** (using official Helm chart)
- **S3 Buckets** for your public/private key material shares
- **VPC Endpoints** for secure connections to other 12 parties
- **IAM Roles** with IRSA for your AWS service access
- **RDS Database** (optional, for your KMS connector)

---

## Phase 1: Infrastructure Deployment

### Prerequisites
- **1 AWS account** for your party
- **Your assigned party ID** (1-13) from network coordinator
- **Terraform** >= 1.0, **kubectl**, **helm** configured
- **AWS CLI** with admin permissions for your account
- **Network coordination info** from other parties

### Critical Requirements
- **AWS Instance Type**: `c7a.16xlarge` (required for Nitro Enclaves)
- **AMI Version**: `1.32.3-20250620` (specific version required)
- **Memory**: Minimum 32Gi RAM per party (96Gi allocated to Nitro Enclaves)
- **CPU**: Minimum 8 cores (16 cores recommended for production)
- **Storage**: 100Gi+ for key material and logs

### Step 1: Deploy Your Party's Infrastructure

Clone and configure the official Terraform modules:

```bash
git clone https://github.com/zama-ai/terraform-mpc-modules.git
cd terraform-mpc-modules/examples/mpc-party
```

Create your party-specific configuration:

```bash
# Set your party ID (1-13)
export PARTY_ID=1  # Replace with your assigned party ID

cat > party${PARTY_ID}.tfvars << EOF
network_environment = "mainnet"  # or "testnet"
aws_region          = "eu-west-1"

# Your Party Configuration
party_id      = ${PARTY_ID}
party_name    = "mpc-party-${PARTY_ID}"
environment   = "production"
bucket_prefix = "zama-kms-party${PARTY_ID}"

# EKS Configuration
cluster_name         = "kms-party${PARTY_ID}"
namespace           = "kms-threshold"
service_account_name = "kms-party-${PARTY_ID}"
create_namespace    = true
create_irsa         = true

# Node Group Configuration (Nitro Enclaves for 13-party network)
create_nodegroup                         = true
nodegroup_instance_types                 = ["c7a.16xlarge"]
nodegroup_min_size                       = 1
nodegroup_max_size                       = 3
nodegroup_desired_size                   = 1
nodegroup_disk_size                      = 100
nodegroup_capacity_type                  = "ON_DEMAND"
nodegroup_ami_type                       = "AL2023_x86_64_STANDARD"
nodegroup_ami_release_version           = "1.32.3-20250620"
nodegroup_enable_nitro_enclaves         = true
nodegroup_enable_ssm_managed_instance   = true

nodegroup_labels = {
  "nodepool"    = "kms"
  "party-id"    = "${PARTY_ID}"
  "environment" = "production"
}

# Nitro Enclaves Configuration
kms_enabled_nitro_enclaves              = true
kms_image_attestation_sha               = "5292569b5945693afcde78e5a0045f4bf8c0a594d174baf1e6bccdf0e6338ebe46e89207054e0c48d0ec6deef80284ac"
kms_deletion_window_in_days             = 30

# RDS Configuration (for your KMS connector)
enable_rds              = true
rds_db_name             = "kmsconnector"
rds_username            = "kmsconnector"
rds_deletion_protection = true

# Tagging
owner = "party-${PARTY_ID}-ops"
additional_tags = {
  "Project"     = "kms-threshold-13party"
  "Environment" = "production"
  "Party"       = "${PARTY_ID}"
}
EOF
```

Deploy your infrastructure:

```bash
# Initialize and deploy your party's infrastructure
terraform init
terraform plan -var-file="party${PARTY_ID}.tfvars"
terraform apply -var-file="party${PARTY_ID}.tfvars"

# Get cluster credentials
aws eks update-kubeconfig --region eu-west-1 --name kms-party${PARTY_ID}

# Verify your infrastructure
kubectl get nodes -l nodepool=kms
kubectl get namespace kms-threshold
```

**Note**: Other parties will deploy their own infrastructure independently using their own party IDs.

### Step 2: Configure Your Party's Networking

After coordinating with other parties, configure VPC endpoints for secure communication:

```bash
# Deploy your VPC endpoint provider (exposes your services to other parties)
cd ../mpc-network-provider
terraform apply -var="cluster_name=kms-party${PARTY_ID}" \
                -var="service_name=kms-core"

# Deploy VPC endpoint consumer (connects to other 12 parties)
cd ../mpc-network-consumer

# Create configuration for connecting to other parties
cat > other-parties.tfvars << EOF
cluster_name = "kms-party${PARTY_ID}"
external_parties = [
  # Add configurations for other 12 parties (provided by network coordinator)
  {name="party1", service_name="vpc-endpoint-service-name-from-party1"},
  {name="party2", service_name="vpc-endpoint-service-name-from-party2"},
  # ... continue for all other parties except your own
]
EOF

terraform apply -var-file="other-parties.tfvars"
```

**Network Coordination**: You'll need to coordinate with other parties to exchange VPC endpoint service names.

---

## Phase 2: KMS Application Deployment

### Step 1: Configure Helm Values

The KMS uses official Helm charts with StatefulSets. Create production values:

```yaml
# values-party1-prod.yaml
kmsPeers:
  id: 1
  count: 1

kmsCore:
  enabled: true
  image:
    name: ghcr.io/zama-ai/kms/core-service-enclave
    tag: "v0.12.1"
    pullPolicy: IfNotPresent

  # Service Account (created by Terraform)
  serviceAccountName: kms-party-1

  # Environment variables from Terraform ConfigMap
  envFrom:
    configmap:
      name: mpc-party-1
      key:
        coreClientS3Endpoint: CORE_CLIENT__S3_ENDPOINT
        thresholdId: KMS_CORE__THRESHOLD__MY_ID
        privateVaultStorageBucket: KMS_CORE__PRIVATE_VAULT__STORAGE__S3__BUCKET
        privateVaultStoragePrefix: KMS_CORE__PRIVATE_VAULT__STORAGE__S3__PREFIX
        privateVaultKeychainAWSKMSRootKeySpec: KMS_CORE__PRIVATE_VAULT__KEYCHAIN__AWS_KMS__ROOT_KEY_SPEC
        privateVaultKeychainAWSKMSRootKeyID: KMS_CORE__PRIVATE_VAULT__KEYCHAIN__AWS_KMS__ROOT_KEY_ID
        publicVaultStorageBucket: KMS_CORE__PUBLIC_VAULT__STORAGE__S3__BUCKET
        publicVaultStoragePrefix: KMS_CORE__PUBLIC_VAULT__STORAGE__S3__PREFIX

  # Threshold Mode Configuration
  thresholdMode:
    enabled: true
    peersList:
      - id: 1
        host: kms-core-1.kms-threshold.svc.cluster.local
        port: 50001
        ca_certificate:
          pem: |
            -----BEGIN CERTIFICATE-----
            # Party 1 TLS certificate
            -----END CERTIFICATE-----
      - id: 2
        host: party2-external.kms-threshold.svc.cluster.local
        port: 50001
        ca_certificate:
          pem: |
            -----BEGIN CERTIFICATE-----
            # Party 2 TLS certificate
            -----END CERTIFICATE-----
      - id: 3
        host: party3-external.kms-threshold.svc.cluster.local
        port: 50001
        ca_certificate:
          pem: |
            -----BEGIN CERTIFICATE-----
            # Party 3 TLS certificate
            -----END CERTIFICATE-----
      - id: 4
        host: party4-external.kms-threshold.svc.cluster.local
        port: 50001
        ca_certificate:
          pem: |
            -----BEGIN CERTIFICATE-----
            # Party 4 TLS certificate
            -----END CERTIFICATE-----

    # TLS Configuration
    tls:
      enabled: true
      trustedReleases:
        - pcr0: "5292569b5945693afcde78e5a0045f4bf8c0a594d174baf1e6bccdf0e6338ebe46e89207054e0c48d0ec6deef80284ac"
          pcr1: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
          pcr2: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"

    # Performance Tuning
    thresholdValue: 1
    decCapacity: 10000
    minDecCache: 6000
    numSessionsPreproc: 90
    decryptionMode: "NoiseFloodSmall"
    tokioWorkerThreads: 8
    rayonNumThreads: 56

  # Nitro Enclaves Configuration
  nitroEnclave:
    enabled: true
    signed: true
    cpuCount: 48
    memoryGiB: 96
    cid: 20
    eifPath: /app/kms/core/service/enclave.eif
    ports:
      tracing: 4317
      imds: 5000
      sts: 5500
      s3: 6000
      awskms: 7000
      peer: 10000

  # Storage Configuration
  publicVault:
    s3:
      enabled: true
      bucket: # Set via environment variable
      prefix: "PUB-p1/"

  privateVault:
    s3:
      enabled: true
      bucket: # Set via environment variable
      prefix: "PRIV-p1/"
    awskms:
      enabled: true
      rootKeyId: # Set via environment variable
      rootKeySpec: "symm"

  # AWS Configuration
  aws:
    region: eu-west-1

  # Resource Configuration
  resources:
    requests:
      memory: 16Gi
      cpu: 8
    limits:
      memory: 32Gi
      ephemeralStorage: 10Gi
      grpcTimeout: 360
      grpcMaxMessageSize: 104857600

  # Node Selection
  nodeSelector:
    nodepool: kms

  # Service Monitor for Prometheus
  serviceMonitor:
    enabled: true

# Security Context for Enclaves
podSecurityContextForEnclave:
  fsGroup: 1001
  supplementalGroups: [1001]

# Environment
runMode: prod
rustLog: info
```

### Step 2: Deploy KMS Application

```bash
# Add KMS Helm repository (if available) or use local charts
cd /path/to/kms/charts/kms-core

# Deploy KMS for Party 1
helm install kms-party-1 . \
  --namespace kms-threshold \
  --values values-party1-prod.yaml \
  --wait --timeout=10m

# Verify deployment
kubectl get statefulset -n kms-threshold
kubectl get pods -n kms-threshold -l app=kms-core

# Check health
kubectl exec -n kms-threshold kms-core-1 -- \
  kms-health-check live --endpoint localhost:<GRPC_PORT>
```

Repeat for all parties with appropriate values files.

---

## 🔑 Phase 3: Key Generation Process

### Step 1: Validate Cluster Health

```bash
# Create cluster validation script
cat > validate-threshold-cluster.sh << 'EOF'
#!/bin/bash

PARTIES=("party1" "party2" "party3" "party4")
NAMESPACES=("kms-threshold" "kms-threshold" "kms-threshold" "kms-threshold")

echo "Validating KMS threshold cluster..."

for i in "${!PARTIES[@]}"; do
  party="${PARTIES[$i]}"
  namespace="${NAMESPACES[$i]}"
  
  echo "Checking $party..."
  
  # Check StatefulSet status
  if ! kubectl get statefulset kms-core -n "$namespace" | grep -q "1/1"; then
    echo "ERROR: $party StatefulSet not ready"
    exit 1
  fi
  
  # Check pod health
  if ! kubectl exec -n "$namespace" kms-core-1 -- \
       kms-health-check live --endpoint localhost:<GRPC_PORT> | grep -q "Optimal\|Healthy"; then
    echo "ERROR: $party health check failed"
    exit 1
  fi
  
  echo "SUCCESS: $party - OK"
done

echo "SUCCESS: All parties validated successfully"
EOF

chmod +x validate-threshold-cluster.sh
./validate-threshold-cluster.sh
```

### Step 2: Initialize PRSS

```bash
# Enable PRSS initialization job
helm upgrade kms-party-1 . \
  --namespace kms-threshold \
  --values values-party1-prod.yaml \
  --set kmsInit.enabled=true \
  --wait

# Monitor PRSS initialization
kubectl logs -n kms-threshold job/kms-party-1-threshold-init -f

# Validate PRSS setup on all parties
for party in {1..4}; do
  echo "Checking PRSS setup for party $party..."
  # Use health check tool to verify key material and PRSS setup
  kubectl exec -n kms-threshold kms-core-$party -- \
    kms-health-check live --endpoint localhost:<GRPC_PORT>
done
```

### Step 3: Generate Keys

Key generation is typically triggered via smart contracts, but can be monitored:

```bash
# Enable key generation job (if needed for testing)
helm upgrade kms-party-1 . \
  --namespace kms-threshold \
  --values values-party1-prod.yaml \
  --set kmsGenKeys.enabled=true \
  --set kmsGenKeys.keyGenArgs="insecure-key-gen" \
  --set kmsGenKeys.crsGenArgs="insecure-crs-gen --max-num-bits 1024" \
  --wait

# Monitor key generation progress
watch -n 30 'kubectl exec -n kms-threshold kms-core-1 -- \
  kms-health-check live --endpoint localhost:<GRPC_PORT>'

# Check key material using health check tool
kubectl exec -n kms-threshold kms-core-1 -- \
  kms-health-check live --endpoint localhost:<GRPC_PORT>

# This will show:
# - FHE key IDs and counts
# - CRS key availability  
# - Preprocessing material status
# - Storage backend information
```

---

## Monitoring & Operations

### Monitoring Integration

**Prometheus Integration**:
- The Helm chart includes ServiceMonitor configuration for Prometheus scraping
- Metrics exposed on port <METRICS_PORT> at `/metrics` endpoint (default: 9646)
- See [Metrics Documentation](advanced/metrics.md) for complete monitoring setup

**Health Monitoring**:
- Use `kms-health-check` tool for continuous health monitoring
- Configure monitoring frequency based on your operational requirements
- See [Health Check Tool](../../tools/kms-health-check/README.md) for automation options

**Log Aggregation**:
- Configure log collection based on your logging infrastructure (CloudWatch, ELK, etc.)
- KMS logs are available through standard Kubernetes logging mechanisms
- See your Kubernetes platform documentation for log aggregation setup

---

## Security Considerations

### Nitro Enclaves
- **Image Attestation**: Verify `kms_image_attestation_sha` matches official releases
- **PCR Values**: Configure trusted releases in TLS configuration
- **Resource Isolation**: Enclaves get dedicated CPU cores and memory

### Network Security
- **PrivateLink**: All inter-party communication via AWS PrivateLink
- **TLS**: Mutual TLS between all threshold peers
- **Network Policies**: Kubernetes network policies restrict pod communication

### Access Control
- **IRSA**: Service accounts use IAM roles for AWS access
- **S3 Policies**: Least privilege access to buckets
- **KMS Permissions**: Minimal AWS KMS permissions for key operations

---

## Troubleshooting

### StatefulSet Issues
```bash
# Check StatefulSet status
kubectl describe statefulset kms-core -n kms-threshold

# Check pod events
kubectl describe pod kms-core-1 -n kms-threshold

# Check persistent volumes
kubectl get pv,pvc -n kms-threshold
```

### Nitro Enclaves Issues
```bash
# Check enclave daemon
kubectl logs -n kube-system -l app=nitro-enclaves-k8s-daemonset

# Verify enclave device
kubectl exec -n kms-threshold kms-core-1 -- ls -la /dev/nitro_enclaves

# Check enclave logs
kubectl logs -n kms-threshold kms-core-1 -c kms-core-enclave-logger
```

### Inter-Party Connectivity
```bash
# Test VPC endpoint connectivity
kubectl exec -n kms-threshold kms-core-1 -- \
  nc -zv party2-external.kms-threshold.svc.cluster.local 50001

# Check ExternalName services
kubectl get svc -n kms-threshold -o wide

# Verify TLS certificates
kubectl exec -n kms-threshold kms-core-1 -- \
  openssl s_client -connect party2-external.kms-threshold.svc.cluster.local:50001
```

---


**Success Criteria**: A fully operational, production-ready KMS threshold cluster deployed across 4 AWS accounts using official Terraform modules and Helm charts, with Nitro Enclaves security, comprehensive monitoring, and validated cryptographic operations.

**Need Help?** 
- [Emergency Procedures](emergency-procedures.md) for emergency procedures
- [Terraform MPC Modules](https://github.com/zama-ai/terraform-mpc-modules) for infrastructure
- KMS Helm Charts (`charts/kms-core/`) for application deployment
