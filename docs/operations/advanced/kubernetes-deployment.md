# KMS Alternative Kubernetes Deployment Patterns

**Alternative deployment patterns for your party's KMS node in a 13-party threshold network.**

## Overview

This guide covers alternative deployment patterns for your KMS node using Kubernetes. For the **recommended production approach**, see the [Production Deployment Guide](../production-deployment.md) which uses official [Zama Terraform MPC modules](https://github.com/zama-ai/terraform-mpc-modules).

This guide provides alternative patterns for:

- **Custom Infrastructure**: Manual Kubernetes setup without Terraform modules
- **Development/Testing**: Local or non-production deployments
- **Migration Scenarios**: Moving from Docker to Kubernetes
- **Educational Examples**: Understanding KMS Kubernetes architecture

## Architecture Overview

### 13-Party Threshold Network
Your party operates independently while connecting to 12 other parties in a threshold network (t=4):

```
                    13-Party Threshold Network (t=4)
┌─────────────────────────────────────────────────────────────────┐
│                        YOUR PARTY                               │
│                     (Your AWS Account)                          │
│                                                                 │
│    ┌─────────────┐                                             │
│    │   EKS       │                                             │
│    │   Cluster   │                                             │
│    │             │                                             │
│    │ ┌─────────┐ │                                             │
│    │ │KMS Node │ │◄────── PrivateLink ──────┐                 │
│    │ │(StatefulSet)                          │                 │
│    │ └─────────┘ │                          │                 │
│    └─────────────┘                          │                 │
└─────────────────────────────────────────────┼─────────────────┘
                                              │
                    ┌─────────────────────────┼─────────────────┐
                    │                         ▼                 │
                    │              Other 12 Parties            │
                    │         (Independent AWS Accounts)       │
                    │                                           │
                    │  Party 1  Party 2  ...  Party 13        │
                    │    │        │              │             │
                    │    └────────┼──────────────┘             │
                    │             │                            │
                    └─────────────┼────────────────────────────┘
                                  │
                                  ▲
                    Secure PrivateLink Connections
```

### Your Party's Infrastructure
You deploy and manage:
- **1 EKS Cluster** with Nitro Enclaves support
- **S3 Buckets** for your public/private key material storage
- **RDS Database** for your KMS connector (optional)
- **VPC Endpoints** for secure connections to other 12 parties
- **IAM Roles** with IRSA for your AWS service access

---

## Important Note

**For production deployments**, use the [Production Deployment Guide](../production-deployment.md) which provides the complete, tested approach using official Terraform modules.

This guide is for **alternative patterns only** - use when you need custom infrastructure or are in development/testing scenarios.

---

## Alternative Deployment Patterns

### Prerequisites
- **AWS CLI** configured with admin permissions for your account
- **kubectl** and **helm** configured
- **Your party ID** (1-13) assigned by network coordinator
- **Network planning** for cross-account connectivity

### Step 1: Clone Terraform Modules

```bash
git clone https://github.com/zama-ai/terraform-mpc-modules.git
cd terraform-mpc-modules/examples/mpc-party
```

### Step 2: Configure Each Party

Create configuration for each party (repeat for parties 1-4):

```bash
# Party 1 configuration
cat > party1.tfvars << 'EOF'
# Network Environment Configuration
network_environment = "testnet"  # or "mainnet"

# AWS Configuration
aws_region = "eu-west-1"

# MPC Party Configuration
party_id    = 1
party_name  = "mpc-party-1"
environment = "production"

# S3 Bucket Configuration
bucket_prefix   = "zama-kms-threshold-party1"
config_map_name = "mpc-party-1"

# Kubernetes Configuration
cluster_name         = "kms-production-party1"
namespace            = "kms-threshold"
service_account_name = "mpc-party-1"
create_namespace     = true

# IRSA Configuration (recommended for production)
create_irsa = true

# Tagging
owner = "mpc-ops-team"
additional_tags = {
  "Project"     = "kms-threshold"
  "Environment" = "production"
  "Party"       = "1"
}

# RDS Configuration (for KMS connector)
enable_rds              = true
rds_db_name             = "kmsconnector"
rds_username            = "kmsconnector"
rds_deletion_protection = true

# Node Group Configuration
create_nodegroup                         = true
nodegroup_instance_types                 = ["c7a.16xlarge"]
nodegroup_min_size                       = 1
nodegroup_max_size                       = 3
nodegroup_desired_size                   = 1
nodegroup_disk_size                      = 100
nodegroup_capacity_type                  = "ON_DEMAND"
nodegroup_ami_type                       = "AL2023_x86_64_STANDARD"
nodegroup_ami_release_version           = "1.32.3-20250620"

nodegroup_labels = {
  "nodepool"    = "kms"
  "party-id"    = "1"
  "environment" = "production"
}

# Nitro Enclaves Configuration
nodegroup_enable_nitro_enclaves         = true
nodegroup_enable_ssm_managed_instance   = true
kms_enabled_nitro_enclaves              = true
kms_image_attestation_sha               = "5292569b5945693afcde78e5a0045f4bf8c0a594d174baf1e6bccdf0e6338ebe46e89207054e0c48d0ec6deef80284ac"
kms_deletion_window_in_days             = 30
EOF

# Repeat for parties 2, 3, 4 with appropriate party_id and unique names
```

### Step 3: Deploy Infrastructure

Deploy each party in sequence:

```bash
# Deploy Party 1
terraform init
terraform plan -var-file="party1.tfvars"
terraform apply -var-file="party1.tfvars"

# Get cluster credentials
aws eks update-kubeconfig --region eu-west-1 --name kms-production-party1

# Verify deployment
kubectl get nodes -l nodepool=kms
kubectl get pods -n kms-threshold
```

### Step 4: Configure Inter-Party Networking

After all parties are deployed, configure VPC endpoints for secure communication:

```bash
# Deploy VPC endpoint provider (on each party)
cd ../mpc-network-provider
terraform init
terraform apply -var="cluster_name=kms-production-party1" \
                -var="service_name=kms-threshold-service"

# Deploy VPC endpoint consumer (on each party to connect to others)
cd ../mpc-network-consumer
terraform init
terraform apply -var="cluster_name=kms-production-party1" \
                -var="external_parties=[{name=\"party2\", service_name=\"...\"}]"
```

---

## KMS Application Deployment

### Step 1: Create KMS Configuration

```yaml
# kms-threshold-config.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: kms-threshold-config
  namespace: kms-threshold
data:
  threshold.toml: |
    [service]
    listen_address = "0.0.0.0"
    listen_port = 50100

    [threshold]
    listen_address = "0.0.0.0"
    listen_port = 50001
    my_id = 1
    threshold = 1
    num_sessions_preproc = 90

    [[threshold.peers]]
    party_id = 1
    address = "party1.kms-threshold.svc.cluster.local"
    port = 50001

    [[threshold.peers]]
    party_id = 2
    address = "party2-external.kms-threshold.svc.cluster.local"
    port = 50001

    [[threshold.peers]]
    party_id = 3
    address = "party3-external.kms-threshold.svc.cluster.local"
    port = 50001

    [[threshold.peers]]
    party_id = 4
    address = "party4-external.kms-threshold.svc.cluster.local"
    port = 50001

    [private_vault.storage]
    S3 = { 
      bucket = "zama-kms-threshold-party1-private",
      region = "eu-west-1",
      prefix = "PRIV-p1/"
    }

    [public_vault.storage]
    S3 = { 
      bucket = "zama-kms-threshold-party1-public",
      region = "eu-west-1",
      prefix = "PUB-p1/"
    }

    [telemetry]
    tracing_service_name = "kms-threshold-party1"
    metrics_bind_address = "0.0.0.0:9646"
```

### Step 2: Deploy KMS Application

```yaml
# kms-threshold-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: kms-threshold-party1
  namespace: kms-threshold
  labels:
    app: kms-threshold
    party: "1"
spec:
  replicas: 1
  selector:
    matchLabels:
      app: kms-threshold
      party: "1"
  template:
    metadata:
      labels:
        app: kms-threshold
        party: "1"
    spec:
      serviceAccountName: mpc-party-1
      nodeSelector:
        nodepool: kms
      containers:
      - name: kms-server
        image: ghcr.io/zama-ai/kms/core-service:latest
        ports:
        - containerPort: 50100
          name: grpc
        - containerPort: 50001
          name: p2p
        - containerPort: 9646
          name: metrics
        env:
        - name: KMS_CONFIG_FILE
          value: "/app/config/threshold.toml"
        - name: RUST_LOG
          value: "info"
        # Performance tuning
        - name: TOKIO_WORKER_THREADS
          value: "8"
        - name: RAYON_NUM_THREADS
          value: "56"
        volumeMounts:
        - name: config
          mountPath: /app/config
          readOnly: true
        resources:
          requests:
            memory: "16Gi"
            cpu: "8"
          limits:
            memory: "32Gi"
            cpu: "16"
        readinessProbe:
          exec:
            command: ["/app/kms-core-client/bin/kms-health-check", "live", "--endpoint", "localhost:50100"]
          initialDelaySeconds: 30
          periodSeconds: 10
        livenessProbe:
          exec:
            command: ["/app/kms-core-client/bin/kms-health-check", "live", "--endpoint", "localhost:50100"]
          initialDelaySeconds: 60
          periodSeconds: 30
      volumes:
      - name: config
        configMap:
          name: kms-threshold-config

---
apiVersion: v1
kind: Service
metadata:
  name: kms-threshold-service
  namespace: kms-threshold
  annotations:
    service.beta.kubernetes.io/aws-load-balancer-type: "nlb"
    service.beta.kubernetes.io/aws-load-balancer-internal: "true"
spec:
  selector:
    app: kms-threshold
    party: "1"
  ports:
  - name: grpc
    port: 50100
    targetPort: 50100
  - name: p2p
    port: 50001
    targetPort: 50001
  - name: metrics
    port: 9646
    targetPort: 9646
  type: LoadBalancer
```

### Step 3: Deploy Application

```bash
kubectl apply -f kms-threshold-config.yaml
kubectl apply -f kms-threshold-deployment.yaml

# Wait for deployment
kubectl rollout status deployment/kms-threshold-party1 -n kms-threshold

# Verify health
kubectl exec -n kms-threshold deployment/kms-threshold-party1 -- \
  kms-health-check live --endpoint localhost:50100
```

---

## 🔑 Key Generation Process

### Step 1: Validate All Parties

```bash
# Create validation script
cat > validate-cluster.sh << 'EOF'
#!/bin/bash

PARTIES=("party1" "party2" "party3" "party4")
ENDPOINTS=(
  "kms-threshold-service.kms-threshold.svc.cluster.local:50100"
  "party2-external.kms-threshold.svc.cluster.local:50100"
  "party3-external.kms-threshold.svc.cluster.local:50100"
  "party4-external.kms-threshold.svc.cluster.local:50100"
)

echo "INFO: Validating KMS threshold cluster..."

for i in "${!PARTIES[@]}"; do
  party="${PARTIES[$i]}"
  endpoint="${ENDPOINTS[$i]}"
  
  echo "Checking $party at $endpoint..."
  
  if kubectl exec -n kms-threshold deployment/kms-threshold-party1 -- \
     kms-health-check live --endpoint "$endpoint" | grep -q "Optimal\|Healthy"; then
    echo "SUCCESS: $party - OK"
  else
    echo "ERROR: $party - FAILED"
    exit 1
  fi
done

echo "SUCCESS: All parties validated successfully"
EOF

chmod +x validate-cluster.sh
./validate-cluster.sh
```

### Step 2: Initialize PRSS

```bash
# Run PRSS initialization
kubectl exec -n kms-threshold deployment/kms-threshold-party1 -- \
  kms-init --addresses \
    kms-threshold-service.kms-threshold.svc.cluster.local:50100 \
    party2-external.kms-threshold.svc.cluster.local:50100 \
    party3-external.kms-threshold.svc.cluster.local:50100 \
    party4-external.kms-threshold.svc.cluster.local:50100

# Validate PRSS setup
echo "Validating PRSS initialization..."
for party in {1..4}; do
  # Check S3 for PRSS files (implementation depends on your S3 access method)
  echo "Checking PRSS setup for party $party..."
done
```

### Step 3: Trigger Key Generation

Key generation is typically triggered via smart contracts. Monitor progress:

```bash
# Monitor key generation progress
watch -n 30 'kubectl exec -n kms-threshold deployment/kms-threshold-party1 -- \
  kms-health-check live --endpoint localhost:50100'

# Check logs for progress
kubectl logs -n kms-threshold deployment/kms-threshold-party1 -f
```

---

## Monitoring & Observability

### Prometheus Configuration

```yaml
# prometheus-config.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: prometheus-config
  namespace: monitoring
data:
  prometheus.yml: |
    global:
      scrape_interval: 30s
    
    scrape_configs:
    - job_name: 'kms-threshold'
      kubernetes_sd_configs:
      - role: endpoints
        namespaces:
          names:
          - kms-threshold
      relabel_configs:
      - source_labels: [__meta_kubernetes_service_name]
        action: keep
        regex: kms-threshold-service
      - source_labels: [__meta_kubernetes_endpoint_port_name]
        action: keep
        regex: metrics
```

### Grafana Dashboard

```json
{
  "dashboard": {
    "title": "KMS Threshold Cluster",
    "panels": [
      {
        "title": "Cluster Health Status",
        "type": "stat",
        "targets": [
          {
            "expr": "kms_health_status",
            "legendFormat": "Party {{party_id}}"
          }
        ]
      },
      {
        "title": "Peer Connectivity",
        "type": "graph",
        "targets": [
          {
            "expr": "kms_peers_reachable",
            "legendFormat": "Reachable Peers"
          }
        ]
      },
      {
        "title": "Key Material Count",
        "type": "graph",
        "targets": [
          {
            "expr": "kms_key_material_count",
            "legendFormat": "{{key_type}}"
          }
        ]
      }
    ]
  }
}
```

---

## Security Considerations

### Nitro Enclaves
- **Image Attestation**: Verify `kms_image_attestation_sha` matches official releases
- **KMS Integration**: Enclaves use AWS KMS for secure key derivation
- **Isolation**: Cryptographic operations run in hardware-isolated enclaves

### Network Security
- **PrivateLink**: All inter-party communication via AWS PrivateLink
- **No Internet**: KMS nodes have no direct internet access
- **TLS**: All gRPC communication uses mutual TLS

### Access Control
- **IRSA**: Service accounts use IAM roles for AWS access
- **Least Privilege**: Minimal S3 and KMS permissions
- **Network Policies**: Kubernetes network policies restrict pod communication

---

## Troubleshooting

### Common Issues

#### Pod Scheduling Issues
```bash
# Check node labels and taints
kubectl describe nodes -l nodepool=kms

# Check pod events
kubectl describe pod -n kms-threshold -l app=kms-threshold
```

#### Nitro Enclaves Issues
```bash
# Check enclave daemon status
kubectl logs -n kube-system -l app=nitro-enclaves-k8s-daemonset

# Verify enclave support
kubectl exec -n kms-threshold deployment/kms-threshold-party1 -- \
  ls -la /dev/nitro_enclaves
```

#### Inter-Party Connectivity
```bash
# Test VPC endpoint connectivity
kubectl exec -n kms-threshold deployment/kms-threshold-party1 -- \
  nc -zv party2-external.kms-threshold.svc.cluster.local 50100

# Check ExternalName services
kubectl get svc -n kms-threshold -o wide
```

#### S3 Access Issues
```bash
# Test S3 access with service account
kubectl exec -n kms-threshold deployment/kms-threshold-party1 -- \
  aws s3 ls s3://zama-kms-threshold-party1-private/

# Check IRSA configuration
kubectl describe sa mpc-party-1 -n kms-threshold
```

---

## Production Checklist

### Pre-Deployment
- [ ] AWS accounts and regions planned
- [ ] Network connectivity design completed
- [ ] Security groups and IAM policies reviewed
- [ ] Terraform modules version pinned
- [ ] Backup and disaster recovery plan

### Deployment
- [ ] All 4 parties deployed successfully
- [ ] VPC endpoints configured and tested
- [ ] KMS applications deployed and healthy
- [ ] Inter-party connectivity verified
- [ ] Monitoring and alerting configured

### Post-Deployment
- [ ] PRSS initialization completed
- [ ] Key generation process validated
- [ ] Security audit completed
- [ ] Operational runbooks updated
- [ ] Team training completed

---

**Success Criteria**: A fully operational, production-ready KMS threshold cluster deployed across 4 AWS accounts with secure inter-party communication, comprehensive monitoring, and validated key generation capabilities.

**Need Help?** 
- [Quick Reference](../quick-reference.md) for emergency procedures
- [Terraform MPC Modules](https://github.com/zama-ai/terraform-mpc-modules) for infrastructure details
- [Advanced Troubleshooting](troubleshooting.md) for complex issues
