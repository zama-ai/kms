# KMS Party Operations Guide

**Deploy and manage your party's KMS node in a 13-party threshold network.**

## Single-Party Focus

This documentation helps you deploy **your party's KMS node** as part of a **13-party threshold network** where:
- **Your responsibility**: Deploy and manage your own KMS infrastructure
- **Network**: 13 independent parties (t=4 threshold)
- **Architecture**: Each party runs their own AWS account with EKS cluster

### Essential Documentation (Start Here)
1. [**Quickstart Guide**](quickstart.md) - 30-minute setup for your party
2. [**Production Deployment**](production-deployment.md) - Complete deployment guide with Terraform modules
3. [**Emergency Procedures**](emergency-procedures.md) - Quick fixes and emergency commands
4. [**Monitoring & Metrics**](monitoring.md) - Health checks and comprehensive monitoring
5. [**Configuration Guide**](configuration.md) - Helm values and essential configuration

### Advanced Topics (When Needed)
- [**Advanced Documentation**](advanced/) - Comprehensive guides and detailed procedures

## Target Audience

This documentation is designed for:
- **Infrastructure Engineers** - Deploying and maintaining your party's KMS node
- **DevOps Teams** - Automating your party's KMS operations and CI/CD
- **Site Reliability Engineers** - Monitoring your party's infrastructure
- **Security Teams** - Managing your party's key material and compliance

## Critical Requirements

### **Production Requirements**
- **AWS Instance**: `c7a.16xlarge` with AMI `1.32.3-20250620` (Nitro Enclaves)
- **Memory**: 32Gi minimum for production operations (96Gi allocated to Nitro Enclaves)
- **Network**: PrivateLink connections to other 12 parties required
- **Ports**: 50100 (gRPC), 50001 (P2P - varies by party ID), 9646 (metrics)

> **Common Issues**: See [Emergency Procedures](emergency-procedures.md) for `enable_sys_metrics` deprecation, OOMKilled errors, and resource limit fixes.

## Getting Help

1. **Emergency** - Use [Emergency Procedures](emergency-procedures.md) for immediate fixes
2. **Diagnosis** - Follow the [Monitoring Guide](monitoring.md) health check procedures  
3. **Detailed Help** - Check [Advanced Documentation](advanced/) for comprehensive guides
4. **Escalation** - Contact MPC development team for cryptographic issues

## Emergency Contacts

- **Critical Issues**: Escalate to MPC development team
- **Security Incidents**: Follow your organization's security incident response procedures
- **Infrastructure Issues**: Check with your cloud provider or infrastructure team

---

**Note**: This documentation focuses on operational aspects. For development and API usage, see the [Developer](../developer/) and [Guides](../guides/) sections.
