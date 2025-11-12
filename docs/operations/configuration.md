# KMS Party Configuration Management

**Configure your party's KMS node for optimal performance in a 13-party threshold network.** This guide covers configuration management best practices for KMS deployments, including validation, security, and environment-specific configurations.

## Configuration Overview

KMS uses TOML configuration files with different sections for various components:

- **Service Configuration**: Network binding, TLS, request limits
- **Threshold Configuration**: P2P networking, peer definitions, threshold parameters
- **Storage Configuration**: File, S3, or database storage backends
- **Telemetry Configuration**: Metrics, tracing, and monitoring endpoints

### Configuration References

- **Complete Examples**: See `charts/kms-core/values*.yaml` for production-ready configurations
- **Template Files**: Use `config/` directory templates for different environments
- **Validation**: Use `kms-health-check config --file config.toml` for syntax validation

## Configuration Sections

**Service Configuration**:
- Network binding (address, port, TLS)
- Request limits and timeouts
- Security settings

> ⚠️ **CRITICAL SECURITY WARNING**: The gRPC port (default: 50100) configured in `listen_port` **MUST NEVER** be exposed to the internet. This port handles sensitive cryptographic operations and should only be accessible from localhost or authorized connectors within your secure network. Always use firewall rules to restrict access.

**Threshold Configuration** (13-party mode):
- P2P network settings
- Node identity and peer definitions
- Threshold parameters for fault tolerance

**Storage Configuration**:
- File storage for development
- S3 storage for production (with encryption)
- Database storage for enterprise deployments

**Telemetry Configuration**:
- Distributed tracing endpoints
- Metrics collection settings
- Batch processing parameters

### Configuration Examples

- **Basic Setup**: See `config/` directory for template files
- **Production**: Use `charts/kms-core/values-production.yaml` as reference
- **Development**: Use `charts/kms-core/values-example-local.yaml` for local testing

## Environment-Specific Configurations

### Configuration Templates

**Development Environment**:
- Local file storage for simplicity
- Minimal security requirements
- Local metrics and tracing endpoints
- **Reference**: `config/development.toml` template

**Staging Environment**:
- S3 storage with staging buckets
- TLS enabled with staging certificates
- External tracing and monitoring
- **Reference**: `config/staging.toml` template

**Production Environment**:
- Encrypted S3 storage with KMS keys
- Full TLS configuration with production certificates
- Production-grade timeouts and batch settings
- **Reference**: `config/production.toml` template

### Configuration Management

- **Template Files**: Use `config/` directory templates as starting points
- **Environment Variables**: Substitute environment-specific values
- **Helm Values**: Use `charts/kms-core/values-*.yaml` for Kubernetes deployments
- **Validation**: Always validate configurations before deployment

## Configuration Validation

### Automated Validation

**Basic Validation**:
```bash
# Use the health check tool for syntax validation
kms-health-check config --file config.toml
```

**Environment-Specific Checks**:
- **Production**: Require TLS configuration, S3 storage with encryption, proper service naming
- **Staging**: Ensure no references to production resources
- **Development**: Allow local file storage and simplified configurations

**Threshold Configuration Validation**:
- **Peer Count**: Must have at least `threshold + 1` peers configured
- **Node ID**: `my_id` must match one of the configured `party_id` values
- **Network**: All peer addresses must be reachable
- **Byzantine Fault Tolerance**: Recommend `(2n/3) + 1` nodes online for optimal operation

**Additional Validation Checks**:
- **Storage Sections**: Ensure both `[private_vault]` and `[public_vault]` are configured
- **S3 Configuration**: Verify bucket and region are specified for S3 storage
- **Port Conflicts**: Ensure gRPC and P2P ports are different
- **Network Connectivity**: Test that all peer addresses are reachable

### Configuration Testing

**Live Configuration Testing**:
```bash
# Test configuration syntax before deployment
kms-health-check config --file config.toml

# Test configuration with running KMS instance
kms-health-check live --endpoint localhost:<GRPC_PORT>

# Full validation (config + live instance + key material)
kms-health-check full --config config.toml --endpoint localhost:<GRPC_PORT>

# JSON output for automation
kms-health-check --format json live --endpoint localhost:<GRPC_PORT>
```

**Testing Process**:
1. **Syntax Validation**: Use `kms-health-check config` to validate configuration syntax
2. **Connectivity Testing**: Use `kms-health-check live` to verify service connectivity
3. **Key Material Verification**: Health check tool automatically verifies key availability and storage
4. **Peer Connectivity**: For threshold mode, verifies connectivity to all configured peers

> **Complete Tool Documentation**: See [kms-health-check README](../../tools/kms-health-check/README.md) for full capabilities including timeout configuration, Docker integration, and CI/CD usage.

## Security Best Practices

### Sensitive Data Management

**Security Guidelines**:
- Store sensitive values in environment variables or secret management systems
- Use proper file permissions (600 for configuration files)
- Rotate certificates and secrets regularly
- Avoid hardcoding credentials in configuration files

**Configuration Security**:
- Use TLS certificates for production environments
- Enable encryption for all storage backends
- Implement proper access controls for configuration files
- Use secure naming conventions for environments

### Configuration Encryption

**Encryption at Rest**:
```bash
# Encrypt configuration files (use AES-GCM for better security)
openssl enc -aes-256-gcm -salt -in config.toml -out config.toml.enc -k "$ENCRYPTION_KEY"

# Decrypt for runtime use
openssl enc -aes-256-gcm -d -in config.toml.enc -out /tmp/config.toml -k "$ENCRYPTION_KEY"
```

**Best Practices**:
- Use strong encryption keys (256-bit minimum)
- Store encryption keys securely (separate from encrypted files)
- Use AES-GCM mode for authenticated encryption
- Set secure file permissions (600) for encrypted files

## Configuration Management Automation

### Template-Based Configuration

**Configuration Templates**:
- Use environment-specific templates for different deployment stages
- Implement variable substitution for dynamic values
- Maintain separate templates for centralized vs threshold modes
- Use configuration management tools (Helm, Kustomize, etc.)

**Environment Variables**:
- `ENVIRONMENT`: deployment environment (development, staging, production)
- `PARTY_ID`: party identifier for threshold deployments
- `REGION`: AWS region for storage and services
- `STORAGE_BUCKET`: S3 bucket names for key storage

### GitOps Configuration Management

**Automated Configuration Management**:
- Use CI/CD pipelines for configuration validation and deployment
- Implement configuration drift detection
- Automate security scanning for sensitive data
- Use Kubernetes ConfigMaps for configuration deployment

**Best Practices**:
- Validate configurations before deployment using health check tools
- Scan for hardcoded secrets and credentials
- Use environment-specific validation rules
- Implement automated rollback on validation failures

## Configuration Monitoring

### Configuration Drift Detection

**Drift Detection Process**:
- Compare current configuration against reference/baseline
- Monitor for unauthorized configuration changes
- Alert on configuration drift detection
- Implement automated remediation where appropriate

**Implementation**:
- Use configuration management tools to track changes
- Implement file integrity monitoring
- Set up alerts for configuration file modifications
- Regular configuration audits and compliance checks

### Configuration Backup

**Backup Strategy**:
- Automated daily backups of configuration files
- Version control for configuration changes
- Secure storage of configuration backups
- Regular backup restoration testing

**Backup Components**:
- Configuration files (TOML, YAML)
- TLS certificates and keys
- Environment-specific settings
- Deployment metadata and version information


## Related Documentation

- [Production Deployment](production-deployment.md) - Deployment procedures and best practices
- [Monitoring & Metrics](monitoring.md) - Monitoring and health check procedures
- [Security Checklist](advanced/security.md) - Security hardening and compliance
- [Troubleshooting Guide](advanced/troubleshooting.md) - Configuration-related issue resolution
