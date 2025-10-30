# KMS Party Deployment Quickstart

**Deploy your party's KMS node in a 13-party threshold network.**

## Single-Party Deployment Overview

This guide helps you deploy **your party's KMS node** as part of a **13-party threshold network** where:

- **Your responsibility**: Deploy and manage your own KMS node
- **Network**: 13 independent parties, each managing their own infrastructure
- **Threshold**: `t=4` (tolerates up to 4 Byzantine failures)
- **Architecture**: Each party runs their own AWS account with EKS cluster

### **Your Party's Infrastructure**
- **1 AWS account** with your EKS cluster
- **Nitro Enclaves** for cryptographic isolation  
- **PrivateLink connections** to other 12 parties
- **StatefulSet** for persistent KMS deployment
- **S3 storage** for your key material shares

---

## Quick Start (30-minute setup per party)

### Prerequisites
- **AWS CLI** configured with admin permissions for your account
- **Terraform** >= 1.0, **kubectl**, **helm** installed
- **Your party ID** (1-13) assigned by network coordinator
- **Network configuration** (peer endpoints) from other parties

### Step 1: Infrastructure Deployment (15 minutes)

```bash
# Clone official Terraform modules
git clone https://github.com/zama-ai/terraform-mpc-modules.git
cd terraform-mpc-modules/examples/mpc-party

# Create your party configuration (replace PARTY_ID with your assigned ID 1-13)
export PARTY_ID=1  # Your assigned party ID
cat > party${PARTY_ID}.tfvars << EOF
network_environment = "mainnet"  # or "testnet"
aws_region          = "eu-west-1"

party_id      = ${PARTY_ID}
party_name    = "mpc-party-${PARTY_ID}"
environment   = "production"
bucket_prefix = "zama-kms-party${PARTY_ID}"

cluster_name         = "kms-party${PARTY_ID}"
namespace           = "kms-threshold"
service_account_name = "kms-party-${PARTY_ID}"
create_irsa         = true

# Nitro Enclaves configuration for 13-party network
nodegroup_instance_types                 = ["c7a.16xlarge"]
nodegroup_enable_nitro_enclaves         = true
kms_enabled_nitro_enclaves              = true
kms_image_attestation_sha               = "5292569b5945693afcde78e5a0045f4bf8c0a594d174baf1e6bccdf0e6338ebe46e89207054e0c48d0ec6deef80284ac"

enable_rds = true
owner      = "party-${PARTY_ID}-ops"
EOF

# Deploy your party's infrastructure
terraform init
terraform apply -var-file="party${PARTY_ID}.tfvars" -auto-approve

# Get cluster access
aws eks update-kubeconfig --region eu-west-1 --name kms-party${PARTY_ID}
```

### Step 2: Application Deployment (15 minutes)

```bash
# Navigate to KMS Helm charts
cd /path/to/kms/charts/kms-core

# Create your party's Helm values
cat > values-party${PARTY_ID}.yaml << EOF
kmsPeers:
  id: ${PARTY_ID}
  count: 1

kmsCore:
  enabled: true
  image:
    name: ghcr.io/zama-ai/kms/core-service-enclave
    tag: "v0.12.1"
  
  serviceAccountName: kms-party-${PARTY_ID}
  
  envFrom:
    configmap:
      name: mpc-party-${PARTY_ID}
  
  thresholdMode:
    enabled: true
    thresholdValue: 4  # 13-party network with t=4
    numSessionsPreproc: 90
    tokioWorkerThreads: 8
    rayonNumThreads: 56
    # Peer configuration will be added after network coordination
  
  nitroEnclave:
    enabled: true
    cpuCount: 48
    memoryGiB: 96
  
  nodeSelector:
    nodepool: kms

runMode: prod
rustLog: info
EOF

# Deploy your KMS node
helm install kms-party-${PARTY_ID} . \
  --namespace kms-threshold \
  --values values-party${PARTY_ID}.yaml \
  --wait --timeout=10m

# Verify your deployment
kubectl get statefulset -n kms-threshold
kubectl exec -n kms-threshold kms-core-${PARTY_ID} -- \
  kms-health-check live --endpoint localhost:50100
```

**Result**: Your KMS party node is deployed and healthy. Other parties will deploy their own nodes independently.

---

## Essential Operations

### Health Monitoring
```bash
# Check cluster health
kubectl get pods -n kms-threshold -l app=kms-core

# Run health check on your node
kubectl exec -n kms-threshold kms-core-${PARTY_ID} -- \
  kms-health-check live --endpoint localhost:50100

# Monitor your node's logs
kubectl logs -n kms-threshold kms-core-${PARTY_ID} -f
```

### Network Coordination & Key Generation
```bash
# 1. Check your node health (other parties check theirs independently)
kubectl exec -n kms-threshold kms-core-${PARTY_ID} -- \
  kms-health-check live --endpoint localhost:50100

# 2. Network coordinator will trigger PRSS initialization across all 13 parties
# Monitor your node's participation
kubectl logs -n kms-threshold kms-core-${PARTY_ID} -f

# 3. Monitor key generation process (triggered via smart contracts)
watch -n 30 "kubectl exec -n kms-threshold kms-core-${PARTY_ID} -- \
  kms-health-check live --endpoint localhost:50100"

# 4. Verify your key material after generation
kubectl exec -n kms-threshold kms-core-${PARTY_ID} -- \
  aws s3 ls s3://zama-kms-party${PARTY_ID}-private/PRIV-p${PARTY_ID}/
```

### Troubleshooting
```bash
# Check StatefulSet status
kubectl describe statefulset kms-core -n kms-threshold

# Check Nitro Enclaves
kubectl logs -n kube-system -l app=nitro-enclaves-k8s-daemonset

# Test connectivity to other parties (after network setup)
kubectl exec -n kms-threshold kms-core-${PARTY_ID} -- \
  nc -zv party1-external.kms-threshold.svc.cluster.local 50001
```

---

## Next Steps

### For Complete Production Setup
- **[Production Deployment Guide](production-deployment.md)** - Complete single-party deployment guide
- **[Monitoring Basics](monitoring-basics.md)** - Monitor your party's node
- **[Quick Reference](quick-reference.md)** - Emergency procedures for your node

### Network Coordination
- **Peer Configuration**: Coordinate with other 12 parties for PrivateLink endpoints
- **Network Testing**: Validate connectivity to all other parties
- **Key Generation**: Participate in network-wide key generation ceremonies

---

## Success Criteria

After following this quickstart:
- **Your party's infrastructure deployed** via Terraform with Nitro Enclaves
- **Your KMS node running** and passing health checks
- **Your S3 buckets configured** for key material storage
- **Your monitoring enabled** with Prometheus metrics
- **Ready for network coordination** with other 12 parties

**Total Time**: ~30 minutes for your party's deployment

**Need Help?** Check [Quick Reference](quick-reference.md) for emergency procedures or [Production Deployment](production-deployment.md) for detailed configuration options.
