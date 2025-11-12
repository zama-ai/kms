# KMS Security Best Practices

**Security guidelines and hardening procedures for KMS deployments.**

## Security Overview

KMS security involves multiple layers of protection:

- **Network Security**: Firewall rules, network segmentation, access controls
- **Transport Security**: TLS encryption, certificate management
- **Authentication & Authorization**: RBAC, service accounts, access policies  
- **Key Management**: Secure generation, storage, and rotation
- **Storage Security**: Encryption at rest, access controls
- **Audit & Monitoring**: Security logging, alerting, compliance
- **Operational Security**: Incident response, security assessments

### Threat Model
- **External Attackers**: Network-based attacks, unauthorized access attempts
- **Insider Threats**: Privileged access abuse, credential compromise
- **Supply Chain Attacks**: Compromised dependencies, malicious images
- **Infrastructure Compromise**: Cloud provider breaches, hardware attacks

## Network Security

### Firewall Configuration

**Essential Port Access**:

> 🚨 **CRITICAL**: **Port 50100 (gRPC)** - **NEVER EXPOSE TO INTERNET**
> This port handles sensitive cryptographic operations and MUST be restricted to localhost/authorized connectors only. Internet exposure creates severe security vulnerabilities.

- **Port 50001 (P2P)**: Allow only between KMS threshold nodes
- **Port 9646 (Metrics)**: Restrict to monitoring systems only  
- **SSH/Management**: Limit to management networks only

### Recommended Deployment Pattern

**Co-location with Connector**:
- **Ideal Setup**: Deploy KMS and connector on the same VM/container for maximum security
- **Localhost Communication**: Eliminates network exposure of gRPC port entirely
- **Reduced Attack Surface**: No network-based attacks possible on gRPC endpoint
- **Simplified Firewall Rules**: No need for complex port access controls

**Benefits of Co-location**:
- gRPC communication stays within localhost (0.0.0.0)
- Zero network exposure of sensitive cryptographic operations
- Simplified security configuration and monitoring
- Reduced latency between KMS and connector

**Implementation**:
- Use cloud provider security groups (AWS Security Groups, etc.)
- Configure Kubernetes NetworkPolicies for pod-level restrictions
- Implement firewall rules at the host level if needed
- Block all unnecessary ports and protocols

### Network Segmentation

**Kubernetes NetworkPolicies**: Use NetworkPolicies to restrict pod-to-pod communication:
- Allow gRPC traffic only from authorized clients
- Restrict P2P traffic to KMS nodes only
- Limit monitoring access to designated systems
- Block unnecessary egress traffic

**Reference**: See `charts/kms-core/templates/networkpolicy.yaml` for NetworkPolicy examples.

## Transport Security (TLS)

### Certificate Management

**TLS Requirements**:
- **TLS 1.3**: Use latest TLS version for all communications
- **Strong Ciphers**: Configure secure cipher suites only
- **Certificate Validation**: Enforce certificate verification
- **Perfect Forward Secrecy**: Enable PFS for all connections

**Certificate Sources**:
- **Production**: Use enterprise PKI or cloud certificate services (AWS ACM, etc.)
- **Development**: Use cert-manager or similar automated certificate management
- **Testing**: Generate self-signed certificates as needed

**Key Management**:
- Store private keys securely (Kubernetes secrets, cloud key management)
- Use proper file permissions (600 for private keys)
- Implement automated certificate rotation
- Monitor certificate expiry dates

### TLS Configuration

**TLS Setup Requirements**:
- Configure TLS certificates for service and threshold endpoints
- Use proper certificate paths for your environment
- Enable client certificate verification for enhanced security
- Replace placeholders (`<NAMESPACE>`) with actual values

**Configuration Reference**: See `charts/kms-core/values-*.yaml` for TLS configuration examples and `config/` directory templates.

### Certificate Rotation

**Automated Rotation**:
- Use cert-manager for Kubernetes environments
- Implement monitoring for certificate expiry (30-day warning threshold)
- Set up automated renewal processes
- Test certificate rotation in non-production environments

**Manual Rotation Process**:
1. Generate new certificates with same CN/SAN
2. Update Kubernetes secrets or configuration
3. Restart KMS services to load new certificates
4. Verify connectivity after rotation

## Key Management Security

### Key Generation Security

**Entropy Requirements**:
- Ensure sufficient system entropy (>1000 bits available)
- Use hardware random number generators when available
- Consider entropy-gathering daemons (haveged) for virtual environments

**Secure Key Storage**:
- Set proper directory permissions (700 for key directories)
- Use secure file permissions (600 for private keys, 644 for public keys)
- Implement proper ownership (dedicated KMS user/group)
- Use umask 077 during key generation operations

### Key Storage Security

**Encryption at Rest**:
- Use server-side encryption for all storage backends (S3, database)
- Implement customer-managed encryption keys (AWS KMS, etc.)
- Consider additional client-side encryption layers for sensitive data
- Enable encryption for backup and disaster recovery storage

**Storage Configuration Example**:
```toml
[private_vault.storage]
S3 = { 
  bucket = "<PRIVATE_BUCKET>",
  region = "<REGION>",
  prefix = "prod/encrypted/",
  encryption = "aws:kms",
  kms_key_id = "<KMS_KEY_ARN>"
}
```

### Hardware Security Module (HSM) Integration

**HSM Benefits**:
- Hardware-based key protection
- FIPS 140-2 Level 3+ compliance
- Tamper-resistant key storage
- Hardware-based random number generation

**Implementation**: Configure HSM integration for production environments requiring the highest security levels.

## Access Control & Authentication

### Role-Based Access Control (RBAC)

**Principle of Least Privilege**:
- Grant minimum necessary permissions for each role
- Separate read-only and administrative access
- Use namespace-scoped roles where possible
- Regular access reviews and permission audits

**Common Roles**:
- **KMS Operators**: Read/update KMS resources, view logs
- **Monitoring**: Read-only access to metrics and health endpoints
- **Security Auditors**: Read-only access for compliance verification

**Reference**: See `charts/kms-core/templates/rbac.yaml` for RBAC examples.

### Service Account Security

**Security Best Practices**:
- Disable automatic service account token mounting when not needed
- Use dedicated service accounts for each component
- Implement IRSA (IAM Roles for Service Accounts) for cloud permissions
- Rotate service account tokens regularly

**Configuration Guidelines**:
- Set `automountServiceAccountToken: false` by default
- Mount tokens manually only when required
- Use workload identity for cloud provider integration

## Audit & Monitoring

### Security Event Logging

**Logging Configuration**:
```toml
[telemetry]
tracing_service_name = "kms-<ENVIRONMENT>"
tracing_endpoint = "https://<LOGGING_ENDPOINT>/api/traces"
metrics_bind_address = "0.0.0.0:<METRICS_PORT>"
```

**Security Events to Monitor**:
- Authentication failures and unauthorized access attempts
- Key operations and cryptographic events
- Network connection anomalies
- Certificate expiry and rotation events
- Configuration changes and administrative actions

### Security Monitoring

**Essential Security Alerts**:
- **Authentication Failures**: Rate > 5 failures/minute
- **Unauthorized Access**: Any unauthorized request attempts
- **Certificate Expiry**: Certificates expiring within 30 days
- **Key Operation Anomalies**: Unusual key operation patterns
- **Network Anomalies**: Unexpected connection patterns

**Implementation**: Use Prometheus alerting rules and integrate with your existing monitoring infrastructure.

**Reference**: See `charts/kms-core/templates/servicemonitor.yaml` for metrics configuration.

## Container Security

### Secure Container Configuration

**Security Context Requirements**:
- **Non-root user**: Run containers as non-privileged user (UID 1000)
- **Read-only filesystem**: Enable read-only root filesystem
- **Drop capabilities**: Remove all unnecessary Linux capabilities
- **Security profiles**: Use seccomp and AppArmor profiles

**Resource Management**:
- Set appropriate memory and CPU limits
- Limit ephemeral storage usage
- Use persistent volumes for key storage only

**Reference**: See `charts/kms-core/templates/statefulset.yaml` for secure container configuration examples.

### Image Security

**Vulnerability Scanning**:
- Scan container images for vulnerabilities before deployment
- Use tools like Trivy, Clair, or cloud provider scanning services
- Block deployment of images with critical vulnerabilities
- Implement automated scanning in CI/CD pipelines

**Image Management**:
- Use official KMS images from trusted registries
- Verify image signatures and attestations
- Keep base images updated with security patches

## Secrets Management

### Kubernetes Secrets Security

**Best Practices**:
- Use external secret management systems (Vault, AWS Secrets Manager, etc.)
- Implement sealed secrets or external secrets operators
- Rotate secrets regularly
- Avoid storing secrets in configuration files or environment variables

**Secret Types**:
- **TLS certificates**: Store in Kubernetes TLS secrets
- **Database credentials**: Use external secret management
- **Encryption keys**: Store in dedicated key management systems

### External Secrets Integration

**Recommended Solutions**:
- **HashiCorp Vault**: Enterprise secret management
- **AWS Secrets Manager**: Cloud-native secret storage
- **External Secrets Operator**: Kubernetes integration for external systems

**Implementation**: Configure external secret integration based on your infrastructure requirements.

## Development Environment Security

### ⚠️ Critical Warning: Never Use Development for Production

**Development environments are inherently insecure and must never be used for production cryptographic operations.**

**Critical Security Issues with Development Deployments:**
- **Insecure Key Generation**: Development environments use weak entropy sources
- **No Hardware Security**: Missing Nitro Enclaves hardware isolation
- **Weak Network Security**: No PrivateLink, exposed ports, weak TLS configuration
- **Insecure Storage**: Unencrypted key material, no backup procedures
- **No Audit Logging**: Missing security event logging and monitoring
- **Debug Features**: Enabled debug endpoints and verbose logging

**Development Environment Isolation Requirements:**
- **Never connect** development KMS to production networks
- **Isolate** development environments from internet access
- **Use separate** AWS accounts/cloud projects for development
- **Block** all production traffic to development instances
- **Never use** production keys in development environments
- **Generate separate** test keys for development only
- **Delete** all development keys after testing

## Security Compliance

### Security Implementation

**Security Areas**: Implement security controls across all layers:
- **Network Security**: Firewall rules, network segmentation, access controls
- **Transport Security**: TLS encryption, certificate management, cipher configuration
- **Authentication & Authorization**: RBAC, MFA, access reviews, least privilege
- **Key Management**: Secure generation, encryption at rest, rotation, backup procedures
- **Container Security**: Image scanning, security contexts, resource limits
- **Monitoring & Auditing**: Security logging, monitoring rules, incident response

### Compliance Frameworks

#### SOC 2 Type II Compliance

**Key Requirements**:
- **Security**: Access controls, network security, vulnerability management
- **Availability**: Monitoring, alerting, incident response procedures
- **Processing Integrity**: Data validation, checksums, audit trails
- **Confidentiality**: Encryption at rest and in transit, access controls
- **Privacy**: Data handling, retention policies, user consent

**Implementation**: Work with your compliance team to implement appropriate controls and documentation.

#### FIPS 140-2 Compliance

**Configuration Requirements**:
- Use FIPS-approved cryptographic algorithms only
- Configure TLS 1.3 with approved cipher suites
- Use certified hardware security modules where required
- Implement proper entropy sources for key generation

**Note**: FIPS compliance may require specific hardware and software configurations.

### Security Assessment

**Regular Assessment Activities**:
- **Vulnerability Scanning**: Regular scans of container images and infrastructure
- **Penetration Testing**: Annual or bi-annual security testing
- **Configuration Reviews**: Quarterly security configuration audits
- **Access Reviews**: Regular review of user access and permissions
- **Compliance Audits**: Annual compliance framework assessments

**Tools and Processes**:
- Use automated security scanning tools
- Implement security testing in CI/CD pipelines
- Document security procedures and incident response plans
- Maintain security metrics and reporting dashboards

## Incident Response

### Security Incident Response Plan

**Response Phases**:
1. **Detection & Analysis**: Monitor alerts, analyze incidents, determine scope
2. **Containment**: Isolate systems, prevent damage, preserve evidence
3. **Eradication & Recovery**: Remove threats, restore from backups, apply patches
4. **Post-Incident**: Document lessons learned, update procedures, conduct reviews

### Emergency Response Procedures

**Immediate Actions**:
- **System Compromise**: Scale down affected deployments, isolate network access
- **Data Breach**: Stop services, notify security team, preserve evidence
- **Unauthorized Access**: Revoke active sessions, rotate certificates, review logs

**Emergency Contacts**:
- Follow your organization's security incident response procedures
- Escalate to MPC development team for cryptographic issues
- Contact cloud provider support for infrastructure issues

**Documentation**: Maintain incident logs and post-incident reports for compliance and improvement.

---

## Related Documentation

- [Configuration Management](../configuration.md) - Secure configuration practices
- [Metrics & Monitoring](metrics.md) - Security monitoring and alerting
- [Kubernetes Deployment](kubernetes-deployment.md) - Secure deployment procedures
- [Troubleshooting Guide](troubleshooting.md) - Security-related issue resolution
