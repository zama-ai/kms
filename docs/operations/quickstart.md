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

**Infrastructure Setup**:
- Use [Terraform MPC Modules](https://github.com/zama-ai/terraform-mpc-modules) for infrastructure deployment
- Configure your party ID, AWS region, and Nitro Enclaves settings
- See [Production Deployment Guide](production-deployment.md) for complete Terraform configuration

### Step 2: Application Deployment (15 minutes)

**Application Setup**:
- Use KMS Helm charts (`charts/kms-core/`) for application deployment
- Configure threshold mode with your party ID and peer settings
- See [Configuration Guide](configuration.md) for Helm values reference

**Result**: Your KMS party node is deployed and healthy. Other parties will deploy their own nodes independently.

---

## Essential Operations

### Health Monitoring
**Monitor Your Node**:
- Use `kms-health-check` tool for health verification
- Monitor pod status with `kubectl get pods`
- See [Monitoring & Metrics](monitoring.md) for comprehensive monitoring setup

### Network Coordination & Key Generation
**Multi-Party Operations**:
- Coordinate with other parties for PRSS initialization
- Monitor key generation process through health checks
- Verify key material availability after generation
- See [Production Deployment Guide](production-deployment.md) for detailed procedures

### Troubleshooting
**Common Issues**:
- Check StatefulSet and pod status
- Verify Nitro Enclaves functionality
- Test network connectivity to other parties
- See [Emergency Procedures](emergency-procedures.md) for emergency procedures

---

## Next Steps

### For Complete Production Setup
- **[Production Deployment Guide](production-deployment.md)** - Complete single-party deployment guide
- **[Monitoring & Metrics](monitoring.md)** - Monitor your party's node
- **[Emergency Procedures](emergency-procedures.md)** - Emergency procedures for your node

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

**Need Help?** Check [Emergency Procedures](emergency-procedures.md) for emergency procedures or [Production Deployment](production-deployment.md) for detailed configuration options.
