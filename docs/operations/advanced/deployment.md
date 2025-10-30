# Alternative Deployment Patterns

**Reference guide for alternative KMS deployment approaches.**

> **Production Deployments**: Use [Production Deployment Guide](../production-deployment.md) with official [Terraform MPC modules](https://github.com/zama-ai/terraform-mpc-modules) and KMS Helm charts (`charts/kms-core/`).

This guide provides **references and concepts** for alternative deployment scenarios.

## Deployment Options

### Production (Recommended)
- **Guide**: [Production Deployment](../production-deployment.md)
- **Infrastructure**: [Terraform MPC Modules](https://github.com/zama-ai/terraform-mpc-modules)
- **Application**: KMS Helm Charts (`charts/kms-core/`)
- **Context**: 13-party threshold network, single-party management

### Development & Testing
- **Local Kubernetes**: Use `charts/kms-core/values-example-local.yaml`
- **Configuration**: See [Configuration Guide](../configuration.md) for TOML examples
- **Docker Development**: See Docker setup examples below

### Custom Infrastructure
- **Manual Kubernetes**: Adapt `charts/kms-core/templates/` for custom deployments
- **Cloud Providers**: Use Terraform modules as reference for other clouds
- **Bare Metal**: Extract configuration patterns from Helm values

## Critical Requirements

> **Complete Requirements**: See [Production Deployment Guide](../production-deployment.md#critical-requirements) for detailed infrastructure, security, and network requirements.

### Quick Reference
- **AWS Instance**: `c7a.16xlarge` (Nitro Enclaves required)
- **Memory**: 16Gi minimum (32Gi recommended) 
- **Ports**: 50100 (gRPC), 50001 (P2P), 9646 (metrics)
- **Network**: PrivateLink for 13-party connectivity

## Alternative Deployment References

### Docker Development

**Quick Docker Setup:**
```bash
# Development centralized KMS
mkdir -p /opt/kms/{config,keys,logs}

# Basic configuration (see Configuration Guide for complete examples)
cat > /opt/kms/config/centralized.toml << 'EOF'
[service]
listen_address = "0.0.0.0"
listen_port = 50100

[private_vault.storage]
File = { path = "/app/keys" }

[telemetry]
tracing_service_name = "kms-dev"
metrics_bind_address = "0.0.0.0:9646"
EOF

# Run with Docker
docker run -d \
  --name kms-dev \
  -p 50100:50100 -p 9646:9646 \
  -v /opt/kms/config:/app/config:ro \
  -v /opt/kms/keys:/app/keys \
  ghcr.io/zama-ai/kms/core-service:latest
```

**For Production**: Use the [Production Deployment Guide](../production-deployment.md) with Helm charts

### Manual Kubernetes
> **Templates**: See `charts/kms-core/templates/` for Kubernetes manifests.

- **StatefulSet**: Persistent KMS node deployment patterns
- **Services**: Internal and external service configuration  
- **ConfigMaps**: Configuration management examples
- **PVCs**: Storage configuration patterns

### Configuration Management
> **Configuration**: See [Configuration Guide](../configuration.md) for complete TOML configuration examples.

- **Environment-specific**: Development, staging, production patterns
- **Validation**: Configuration validation scripts and procedures
- **Security**: TLS and encryption configuration examples

## Key Concepts

### Single-Party Deployment
- **Your Responsibility**: Deploy and manage your own KMS node
- **Network Coordination**: Connect to 12 other independent parties
- **Threshold Requirements**: Need 5+ parties online for t=4 operations

### Infrastructure Patterns
- **Kubernetes StatefulSet**: Persistent storage and stable network identity
- **PrivateLink Networking**: Secure cross-party connectivity
- **S3 Storage**: Encrypted key material storage per party

## Deployment Checklist

### Pre-Deployment
- [ ] Review [Production Deployment Guide](../production-deployment.md) requirements
- [ ] Infrastructure provisioned using [Terraform modules](https://github.com/zama-ai/terraform-mpc-modules)
- [ ] Network coordination completed with other parties
- [ ] Configuration validated using [Configuration Guide](../configuration.md)

### Deployment
- [ ] Deploy using KMS Helm charts (`charts/kms-core/`)
- [ ] Verify health using [Monitoring Guide](../monitoring-basics.md)
- [ ] Test connectivity to other parties
- [ ] Complete PRSS initialization (coordinated with network)

### Post-Deployment
- [ ] Run comprehensive health checks
- [ ] Verify monitoring and alerting
- [ ] Test backup and recovery procedures
- [ ] Update documentation

## Related Documentation

- [Production Deployment](../production-deployment.md) - Recommended production approach
- [Configuration Guide](../configuration.md) - Complete configuration reference
- [Monitoring Basics](../monitoring-basics.md) - Health checks and monitoring
- [Troubleshooting](troubleshooting.md) - Issue resolution procedures
- [Security Checklist](security.md) - Security hardening procedures

---

**Maintenance Note**: This guide provides references to authoritative sources. For detailed examples and configurations, always refer to the linked official documentation and source files to ensure you have the latest versions.
