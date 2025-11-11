# KMS Kubernetes Deployment Reference

**Reference guide for alternative Kubernetes deployment patterns.**

> **Production Deployments**: Use the [Production Deployment Guide](../production-deployment.md) with official [Zama Terraform MPC modules](https://github.com/zama-ai/terraform-mpc-modules) for complete infrastructure setup.

## Overview

This guide provides **reference patterns** for alternative Kubernetes deployment scenarios when the standard production approach doesn't fit your requirements.

### When to Use This Guide
- **Custom Infrastructure**: Manual Kubernetes setup without Terraform modules
- **Development/Testing**: Local or non-production deployments  
- **Migration Scenarios**: Moving from Docker to Kubernetes
- **Educational Examples**: Understanding KMS Kubernetes architecture

### Production Approach
For production deployments, follow the [Production Deployment Guide](../production-deployment.md) which uses:
- **Infrastructure**: [Terraform MPC Modules](https://github.com/zama-ai/terraform-mpc-modules)
- **Application**: KMS Helm Charts (`charts/kms-core/`)
- **Documentation**: Complete setup procedures and network coordination

## Architecture Overview

### 13-Party Threshold Network
Your party operates independently while connecting to 12 other parties in a threshold network (t=4):

- **Your Responsibility**: Deploy and manage your own KMS infrastructure
- **Network**: 13 independent parties with secure PrivateLink connections
- **Threshold**: Need 5+ parties online for cryptographic operations

### Infrastructure Components
- **EKS Cluster** with Nitro Enclaves support
- **S3 Buckets** for key material storage (per party)
- **VPC Endpoints** for secure cross-party connectivity
- **IAM Roles** with IRSA for AWS service access

## Deployment Patterns

### Prerequisites
- AWS CLI configured with admin permissions
- kubectl and helm configured
- Your party ID (1-13) assigned by network coordinator
- Network planning completed with other parties

### Infrastructure Setup

**Recommended**: Use [Terraform MPC Modules](https://github.com/zama-ai/terraform-mpc-modules) for infrastructure provisioning. See the [Production Deployment Guide](../production-deployment.md) for complete instructions.

**Alternative**: For custom infrastructure needs, adapt the Terraform modules as reference for:
- EKS cluster configuration with Nitro Enclaves
- S3 bucket setup with proper encryption
- VPC endpoint configuration for inter-party connectivity
- IAM roles and service account setup

### Application Deployment

Use the KMS Helm charts for application deployment. See [Configuration Guide](../configuration.md) for complete Helm values reference.

### Configuration Reference

**Threshold Configuration**:
- Configure service and threshold ports (50100 for gRPC, 50001 for P2P)
- Set party ID and threshold value (t=4 for 13-party network)
- Configure peer addresses (provided by network coordinator)
- Set up S3 storage buckets for private and public key material
- Configure telemetry and metrics endpoints

**Important Notes**:
- The gRPC endpoint should only be accessible to localhost/connector
- Network coordinator provides the complete peer list for all 13 parties
- See [Configuration Guide](../configuration.md) for complete configuration templates

## Key Generation Process

### PRSS Initialization
**Coordinated Setup**:
- Enable PRSS initialization in Helm values (`kmsInit.enabled=true`)
- Coordinate with network coordinator for multi-party initialization
- Verify PRSS setup completion in initialization job logs

### Validation
**Deployment Verification**:
- Check StatefulSet and pod status
- Verify health using `kms-health-check` tool
- Test inter-party connectivity to other parties
- See [Monitoring Guide](../monitoring.md) for complete validation procedures

## Security Considerations

### Nitro Enclaves
- **Required**: AWS instances with Nitro Enclaves support (`c7a.16xlarge`)
- **Attestation**: Verify image attestation SHA matches official releases
- **Isolation**: Cryptographic operations run in hardware-isolated enclaves

### Network Security
- **PrivateLink**: All inter-party communication via AWS PrivateLink (planned implementation)
- **Access Control**: gRPC endpoint (port 50100) must be restricted to localhost access only
- **TLS**: All P2P communication uses mutual TLS

### Access Control
- **IRSA**: Service accounts use IAM roles for AWS access
- **Least Privilege**: Minimal S3 and KMS permissions required
- **Network Policies**: Kubernetes network policies restrict pod communication

## Troubleshooting

### Common Issues

**Pod Scheduling**:
- Verify node selection and scheduling constraints
- Check pod placement and resource allocation

**Connectivity**:
- Test service connectivity on configured ports
- Check inter-party connectivity to other parties

**Storage Access**:
- Test storage access using `kms-health-check` tool
- Verify service account and IRSA configuration
- Check S3 bucket permissions and access

## Related Documentation

- [Production Deployment](../production-deployment.md) - Recommended production approach
- [Configuration Guide](../configuration.md) - Complete configuration reference  
- [Monitoring & Metrics](../monitoring.md) - Health checks and monitoring
- [Troubleshooting](troubleshooting.md) - Issue resolution procedures

---

**Maintenance Note**: This guide provides reference patterns only. For production deployments, always use the [Production Deployment Guide](../production-deployment.md) with official Terraform modules and Helm charts to ensure you have the latest tested configurations.
