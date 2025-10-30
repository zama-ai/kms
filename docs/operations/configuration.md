# KMS Party Configuration Management

**Configure your party's KMS node for optimal performance in a 13-party threshold network.** This guide covers configuration management best practices for KMS deployments, including validation, security, and environment-specific configurations.

## Configuration Overview

KMS uses TOML configuration files with different sections for various components:

```toml
# Example complete configuration
[service]
listen_address = "0.0.0.0"
listen_port = 50100

[threshold]  # Only for 13-party threshold mode
listen_address = "0.0.0.0"
listen_port = 50001
my_id = ${PARTY_ID}  # Your assigned party ID (1-13)
threshold = 4        # 13-party network threshold

# Configure all 13 parties (network coordinator provides full list)
[[threshold.peers]]
party_id = 1
address = "party1-external.kms-threshold.svc.cluster.local"
port = 50001
# ... repeat for all 13 parties

[private_vault]
[private_vault.storage]
File = { path = "/app/keys/PRIV-p1" }

[public_vault]
[public_vault.storage]
File = { path = "/app/keys" }

[telemetry]
tracing_service_name = "kms-threshold-node1"
metrics_bind_address = "0.0.0.0:9646"
```

## Configuration Sections

### Service Configuration

```toml
[service]
# Network binding
listen_address = "0.0.0.0"  # Bind to all interfaces
listen_port = 50100         # Default gRPC port

# TLS configuration (optional)
tls_cert_path = "/app/certs/server.crt"
tls_key_path = "/app/certs/server.key"

# Request limits
max_request_size = 4194304  # 4MB default
request_timeout_secs = 30   # 30 seconds default
```

### Threshold Configuration

```toml
[threshold]
# P2P network binding
listen_address = "0.0.0.0"
listen_port = 50001

# Node identity (1-based indexing)
my_id = 1

# Threshold parameter (max failures tolerated)
threshold = 1

# Peer definitions
[[threshold.peers]]
party_id = 1
address = "kms-node1.example.com"
port = 50001
# Optional TLS certificate for this peer
tls_cert = "/app/certs/peer1.crt"

[[threshold.peers]]
party_id = 2
address = "kms-node2.example.com"
port = 50001
```

**Key Points:**
- `my_id` must match one of the `party_id` values in peers
- `threshold + 1` is the minimum number of nodes needed for operations
- For Byzantine fault tolerance, recommend `(2n/3) + 1` nodes online
- All nodes should have identical peer configurations

### Storage Configuration

#### File Storage
```toml
[private_vault]
[private_vault.storage]
File = { path = "/app/keys/PRIV-p1" }

[public_vault]
[public_vault.storage]
File = { path = "/app/keys" }
```

#### S3 Storage
```toml
[private_vault]
[private_vault.storage]
S3 = { 
  bucket = "kms-private-keys",
  region = "us-west-2",
  prefix = "node1/",
  encryption = "AES256",
  kms_key_id = "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012"
}

[public_vault]
[public_vault.storage]
S3 = { 
  bucket = "kms-public-keys",
  region = "us-west-2",
  prefix = "shared/"
}
```

#### Database Storage
```toml
[private_vault]
[private_vault.storage]
Database = {
  connection_string = "postgresql://user:pass@localhost:5432/kms_private",
  table_prefix = "node1_"
}
```

### Telemetry Configuration

```toml
[telemetry]
# Service identification
tracing_service_name = "kms-production-node1"

# Distributed tracing
tracing_endpoint = "http://jaeger:14268/api/traces"
tracing_otlp_timeout_ms = 5000

# Metrics endpoint
metrics_bind_address = "0.0.0.0:9646"

# Batch processing
batch = {
  max_export_batch_size = 512,
  max_export_timeout_millis = 30000,
  max_queue_size = 2048
}
```

## Environment-Specific Configurations

### Development Environment

```toml
# config/development.toml
[service]
listen_address = "127.0.0.1"
listen_port = 50100

[private_vault]
[private_vault.storage]
File = { path = "./keys" }

[public_vault]
[public_vault.storage]
File = { path = "./keys" }

[telemetry]
tracing_service_name = "kms-dev"
# No external tracing in development
metrics_bind_address = "127.0.0.1:9646"
```

### Staging Environment

```toml
# config/staging.toml
[service]
listen_address = "0.0.0.0"
listen_port = 50100
tls_cert_path = "/app/certs/staging.crt"
tls_key_path = "/app/certs/staging.key"

[private_vault]
[private_vault.storage]
S3 = { 
  bucket = "kms-staging-private",
  region = "us-west-2",
  prefix = "staging/",
  encryption = "AES256"
}

[public_vault]
[public_vault.storage]
S3 = { 
  bucket = "kms-staging-public",
  region = "us-west-2",
  prefix = "staging/"
}

[telemetry]
tracing_service_name = "kms-staging"
tracing_endpoint = "http://jaeger-staging:14268/api/traces"
metrics_bind_address = "0.0.0.0:9646"
```

### Production Environment

```toml
# config/production.toml
[service]
listen_address = "0.0.0.0"
listen_port = 50100
tls_cert_path = "/app/certs/production.crt"
tls_key_path = "/app/certs/production.key"
max_request_size = 8388608  # 8MB for production
request_timeout_secs = 60   # Longer timeout for production

[private_vault]
[private_vault.storage]
S3 = { 
  bucket = "kms-prod-private-keys",
  region = "us-west-2",
  prefix = "prod/",
  encryption = "AES256",
  kms_key_id = "arn:aws:kms:us-west-2:123456789012:key/prod-kms-key"
}

[public_vault]
[public_vault.storage]
S3 = { 
  bucket = "kms-prod-public-keys",
  region = "us-west-2",
  prefix = "prod/"
}

[telemetry]
tracing_service_name = "kms-production"
tracing_endpoint = "https://jaeger-prod.example.com/api/traces"
tracing_otlp_timeout_ms = 10000
metrics_bind_address = "0.0.0.0:9646"

# Production batch settings for better performance
batch = {
  max_export_batch_size = 1024,
  max_export_timeout_millis = 60000,
  max_queue_size = 4096
}
```

## Configuration Validation

### Automated Validation

```bash
#!/bin/bash
# validate-config.sh - Comprehensive configuration validation

CONFIG_FILE="$1"
ENVIRONMENT="${2:-development}"

if [ ! -f "$CONFIG_FILE" ]; then
    echo "ERROR: Configuration file not found: $CONFIG_FILE"
    exit 1
fi

echo "Validating KMS configuration: $CONFIG_FILE"
echo "Environment: $ENVIRONMENT"

# 1. Syntax validation using the health check tool
echo "Checking configuration syntax..."
if ! kms-health-check config --file "$CONFIG_FILE"; then
    echo "ERROR: Configuration syntax validation failed"
    exit 1
fi
echo "SUCCESS: Configuration syntax is valid"

# 2. Environment-specific validations
case "$ENVIRONMENT" in
    "production")
        echo "Applying production-specific validations..."
        
        # Check for secure storage
        if grep -q 'File.*path.*"\./keys"' "$CONFIG_FILE"; then
            echo "ERROR: Production should not use local file storage"
            exit 1
        fi
        
        # Check for TLS configuration
        if ! grep -q 'tls_cert_path\|tls_key_path' "$CONFIG_FILE"; then
            echo "ERROR: Production requires TLS configuration"
            exit 1
        fi
        
        # Check for encryption
        if grep -q 'S3.*=' "$CONFIG_FILE" && ! grep -q 'encryption.*=.*"AES256"' "$CONFIG_FILE"; then
            echo "WARNING: S3 encryption not explicitly configured"
        fi
        
        # Check for proper service name
        if ! grep -q 'tracing_service_name.*=.*".*prod.*"' "$CONFIG_FILE"; then
            echo "WARNING: Service name should indicate production environment"
        fi
        ;;
        
    "staging")
        echo "Applying staging-specific validations..."
        
        # Ensure staging doesn't reference production resources
        if grep -q 'prod\|production' "$CONFIG_FILE"; then
            echo "ERROR: Staging configuration should not reference production resources"
            exit 1
        fi
        ;;
        
    "development")
        echo "Applying development-specific validations..."
        
        # Warn about external dependencies in development
        if grep -q 'tracing_endpoint' "$CONFIG_FILE"; then
            echo "WARNING: External tracing configured in development"
        fi
        ;;
esac

# 3. Threshold-specific validations
if grep -q '\[threshold\]' "$CONFIG_FILE"; then
    echo "Validating threshold configuration..."
    
    # Extract threshold value and peer count
    THRESHOLD=$(grep -E '^threshold\s*=' "$CONFIG_FILE" | sed 's/.*=\s*//' | tr -d ' ')
    PEER_COUNT=$(grep -c '\[\[threshold\.peers\]\]' "$CONFIG_FILE")
    
    if [ -n "$THRESHOLD" ] && [ -n "$PEER_COUNT" ]; then
        MIN_REQUIRED=$((THRESHOLD + 1))
        if [ "$PEER_COUNT" -lt "$MIN_REQUIRED" ]; then
            echo "ERROR: Insufficient peers: $PEER_COUNT configured, need at least $MIN_REQUIRED for threshold $THRESHOLD"
            exit 1
        fi
        
        # Check for Byzantine fault tolerance
        HEALTHY_REQUIRED=$(( (2 * PEER_COUNT) / 3 + 1 ))
        echo "INFO: Threshold configuration:"
        echo "   - Threshold: $THRESHOLD"
        echo "   - Peers configured: $PEER_COUNT"
        echo "   - Minimum required: $MIN_REQUIRED"
        echo "   - Healthy threshold: $HEALTHY_REQUIRED"
        echo "   - Optimal: $PEER_COUNT (all peers online)"
    fi
    
    # Validate my_id is in peers list
    MY_ID=$(grep -E '^my_id\s*=' "$CONFIG_FILE" | sed 's/.*=\s*//' | tr -d ' ')
    if [ -n "$MY_ID" ]; then
        if ! grep -q "party_id = $MY_ID" "$CONFIG_FILE"; then
            echo "ERROR: my_id ($MY_ID) not found in peers list"
            exit 1
        fi
    fi
fi

# 4. Storage validation
echo "Validating storage configuration..."

# Check for required storage sections
if ! grep -q '\[private_vault\]' "$CONFIG_FILE"; then
    echo "ERROR: Missing private_vault configuration"
    exit 1
fi

if ! grep -q '\[public_vault\]' "$CONFIG_FILE"; then
    echo "ERROR: Missing public_vault configuration"
    exit 1
fi

# Validate S3 configuration if present
if grep -q 'S3.*=' "$CONFIG_FILE"; then
    # Check required S3 fields
    if ! grep -q 'bucket.*=' "$CONFIG_FILE"; then
        echo "ERROR: S3 configuration missing bucket"
        exit 1
    fi
    
    if ! grep -q 'region.*=' "$CONFIG_FILE"; then
        echo "ERROR: S3 configuration missing region"
        exit 1
    fi
fi

# 5. Network validation
echo "Validating network configuration..."

# Check for port conflicts
GRPC_PORT=$(grep -E '^listen_port\s*=' "$CONFIG_FILE" | head -1 | sed 's/.*=\s*//' | tr -d ' ')
P2P_PORT=$(grep -A 10 '\[threshold\]' "$CONFIG_FILE" | grep -E '^listen_port\s*=' | sed 's/.*=\s*//' | tr -d ' ')

if [ -n "$GRPC_PORT" ] && [ -n "$P2P_PORT" ] && [ "$GRPC_PORT" = "$P2P_PORT" ]; then
    echo "ERROR: Port conflict: gRPC and P2P ports cannot be the same ($GRPC_PORT)"
    exit 1
fi

echo "SUCCESS: Configuration validation completed successfully"

# 6. Generate validation report
cat << EOF

CONFIGURATION SUMMARY
========================
Environment: $ENVIRONMENT
Configuration file: $CONFIG_FILE
Validation status: PASSED

Network Configuration:
- gRPC port: ${GRPC_PORT:-"50100 (default)"}
- P2P port: ${P2P_PORT:-"N/A (centralized mode)"}

Storage Configuration:
$(grep -A 5 '\[.*_vault\]' "$CONFIG_FILE" | grep -E '(File|S3|Database)' | sed 's/^/- /')

$(if grep -q '\[threshold\]' "$CONFIG_FILE"; then
    echo "Threshold Configuration:"
    echo "- Mode: Threshold"
    echo "- Threshold: ${THRESHOLD:-"unknown"}"
    echo "- Peers: ${PEER_COUNT:-"unknown"}"
    echo "- Node ID: ${MY_ID:-"unknown"}"
else
    echo "Mode: Centralized"
fi)

Telemetry:
$(grep -E '(tracing_service_name|metrics_bind_address)' "$CONFIG_FILE" | sed 's/^/- /')

EOF
```

### Configuration Testing

```bash
#!/bin/bash
# test-config.sh - Test configuration with actual KMS instance

CONFIG_FILE="$1"
TEST_DURATION="${2:-30}"  # Test duration in seconds

echo "🧪 Testing configuration with live KMS instance..."

# Start KMS with test configuration
echo "Starting KMS with configuration: $CONFIG_FILE"
docker run -d --name kms-config-test \
    -v "$(dirname "$CONFIG_FILE"):/app/config:ro" \
    -v "/tmp/kms-test-keys:/app/keys" \
    -p 50100:50100 \
    -e KMS_CONFIG_FILE="/app/config/$(basename "$CONFIG_FILE")" \
    ghcr.io/zama-ai/kms/core-service:latest

# Wait for startup
echo "Waiting for KMS startup..."
sleep 10

# Test connectivity
echo "Testing connectivity..."
if ! kms-health-check live --endpoint localhost:50100; then
    echo "ERROR: Configuration test failed - service not reachable"
    docker logs kms-config-test --tail 50
    docker rm -f kms-config-test
    exit 1
fi

# Run extended test
echo "Running extended test for $TEST_DURATION seconds..."
END_TIME=$(($(date +%s) + TEST_DURATION))

while [ $(date +%s) -lt $END_TIME ]; do
    if ! kms-health-check live --endpoint localhost:50100 >/dev/null 2>&1; then
        echo "ERROR: Service became unhealthy during test"
        docker logs kms-config-test --tail 20
        docker rm -f kms-config-test
        exit 1
    fi
    sleep 5
done

# Cleanup
docker rm -f kms-config-test
rm -rf /tmp/kms-test-keys

echo "SUCCESS: Configuration test completed successfully"
```

## Security Best Practices

### Sensitive Data Management

```bash
#!/bin/bash
# secure-config.sh - Generate secure configuration with secrets

ENVIRONMENT="$1"
OUTPUT_FILE="$2"

# Generate base configuration
cat > "$OUTPUT_FILE" << EOF
[service]
listen_address = "0.0.0.0"
listen_port = 50100
tls_cert_path = "/app/certs/server.crt"
tls_key_path = "/app/certs/server.key"

[private_vault]
[private_vault.storage]
S3 = { 
  bucket = "kms-${ENVIRONMENT}-private",
  region = "us-west-2",
  prefix = "${ENVIRONMENT}/",
  encryption = "AES256"
}

[public_vault]
[public_vault.storage]
S3 = { 
  bucket = "kms-${ENVIRONMENT}-public",
  region = "us-west-2",
  prefix = "${ENVIRONMENT}/"
}

[telemetry]
tracing_service_name = "kms-${ENVIRONMENT}"
metrics_bind_address = "0.0.0.0:9646"
EOF

# Set secure permissions
chmod 600 "$OUTPUT_FILE"
echo "SUCCESS: Secure configuration generated: $OUTPUT_FILE"
echo "WARNING: Remember to:"
echo "   - Store sensitive values in environment variables or secret management"
echo "   - Use proper file permissions (600)"
echo "   - Rotate certificates regularly"
```

### Configuration Encryption

```bash
#!/bin/bash
# encrypt-config.sh - Encrypt configuration files

CONFIG_FILE="$1"
ENCRYPTION_KEY="$2"

if [ -z "$CONFIG_FILE" ] || [ -z "$ENCRYPTION_KEY" ]; then
    echo "Usage: $0 <config-file> <encryption-key>"
    exit 1
fi

# Encrypt configuration
openssl enc -aes-256-cbc -salt -in "$CONFIG_FILE" -out "${CONFIG_FILE}.enc" -k "$ENCRYPTION_KEY"

# Set secure permissions
chmod 600 "${CONFIG_FILE}.enc"
rm "$CONFIG_FILE"  # Remove plaintext version

echo "SUCCESS: Configuration encrypted: ${CONFIG_FILE}.enc"
```

### Decryption for Runtime

```bash
#!/bin/bash
# decrypt-config.sh - Decrypt configuration at runtime

ENCRYPTED_FILE="$1"
ENCRYPTION_KEY="$2"
OUTPUT_FILE="${3:-/tmp/config.toml}"

# Decrypt configuration
openssl enc -aes-256-cbc -d -in "$ENCRYPTED_FILE" -out "$OUTPUT_FILE" -k "$ENCRYPTION_KEY"

# Set secure permissions
chmod 600 "$OUTPUT_FILE"

echo "SUCCESS: Configuration decrypted to: $OUTPUT_FILE"
```

## Configuration Management Automation

### Template-Based Configuration

```bash
#!/bin/bash
# generate-config.sh - Generate configuration from templates

TEMPLATE_DIR="./config-templates"
OUTPUT_DIR="./config"
ENVIRONMENT="$1"
NODE_ID="${2:-1}"

if [ -z "$ENVIRONMENT" ]; then
    echo "Usage: $0 <environment> [node-id]"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

# Load environment-specific variables
case "$ENVIRONMENT" in
    "production")
        STORAGE_BUCKET="kms-prod-keys"
        TRACING_ENDPOINT="https://jaeger-prod.example.com/api/traces"
        TLS_ENABLED="true"
        ;;
    "staging")
        STORAGE_BUCKET="kms-staging-keys"
        TRACING_ENDPOINT="http://jaeger-staging:14268/api/traces"
        TLS_ENABLED="true"
        ;;
    "development")
        STORAGE_BUCKET=""
        TRACING_ENDPOINT=""
        TLS_ENABLED="false"
        ;;
esac

# Generate configuration from template
envsubst < "$TEMPLATE_DIR/kms-config.toml.template" > "$OUTPUT_DIR/${ENVIRONMENT}-node${NODE_ID}.toml"

echo "SUCCESS: Configuration generated: $OUTPUT_DIR/${ENVIRONMENT}-node${NODE_ID}.toml"
```

### Configuration Template Example

```toml
# config-templates/kms-config.toml.template
[service]
listen_address = "0.0.0.0"
listen_port = 50100
${TLS_ENABLED:+tls_cert_path = "/app/certs/server.crt"}
${TLS_ENABLED:+tls_key_path = "/app/certs/server.key"}

${THRESHOLD_MODE:+[threshold]}
${THRESHOLD_MODE:+listen_address = "0.0.0.0"}
${THRESHOLD_MODE:+listen_port = 50001}
${THRESHOLD_MODE:+my_id = ${NODE_ID}}
${THRESHOLD_MODE:+threshold = ${THRESHOLD_VALUE:-1}}

[private_vault]
[private_vault.storage]
${STORAGE_BUCKET:+S3 = { bucket = "${STORAGE_BUCKET}", region = "${AWS_REGION:-us-west-2}", prefix = "${ENVIRONMENT}/node${NODE_ID}/" }}
${STORAGE_BUCKET:-File = { path = "/app/keys/PRIV-p${NODE_ID}" }}

[public_vault]
[public_vault.storage]
${STORAGE_BUCKET:+S3 = { bucket = "${STORAGE_BUCKET}", region = "${AWS_REGION:-us-west-2}", prefix = "${ENVIRONMENT}/public/" }}
${STORAGE_BUCKET:-File = { path = "/app/keys" }}

[telemetry]
tracing_service_name = "kms-${ENVIRONMENT}-node${NODE_ID}"
${TRACING_ENDPOINT:+tracing_endpoint = "${TRACING_ENDPOINT}"}
metrics_bind_address = "0.0.0.0:9646"
```

### GitOps Configuration Management

```yaml
# .github/workflows/config-management.yml
name: Configuration Management

on:
  push:
    paths: ['config/**']
  pull_request:
    paths: ['config/**']

jobs:
  validate-configs:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        environment: [development, staging, production]
        
    steps:
    - uses: actions/checkout@v3
    
    - name: Setup Rust
      uses: actions-rs/toolchain@v1
      with:
        toolchain: stable
    
    - name: Build health check tool
      run: cargo build --release -p kms-health-check
    
    - name: Validate configuration
      run: |
        ./target/release/kms-health-check config \
          --file config/${{ matrix.environment }}.toml
    
    - name: Security scan
      run: |
        # Check for sensitive data in configuration
        if grep -E "(password|secret|key).*=" config/${{ matrix.environment }}.toml; then
          echo "ERROR: Sensitive data found in configuration"
          exit 1
        fi
    
    - name: Environment-specific validation
      run: |
        ./scripts/validate-config.sh config/${{ matrix.environment }}.toml ${{ matrix.environment }}

  deploy-configs:
    needs: validate-configs
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Deploy to Kubernetes ConfigMaps
      run: |
        for env in development staging production; do
          kubectl create configmap kms-config-$env \
            --from-file=config.toml=config/$env.toml \
            --namespace=kms-$env \
            --dry-run=client -o yaml | kubectl apply -f -
        done
```

## Configuration Monitoring

### Configuration Drift Detection

```bash
#!/bin/bash
# detect-config-drift.sh - Detect configuration changes

REFERENCE_CONFIG="$1"
CURRENT_CONFIG="$2"

echo "INFO: Detecting configuration drift..."
echo "Reference: $REFERENCE_CONFIG"
echo "Current: $CURRENT_CONFIG"

# Compare configurations (ignoring comments and whitespace)
if ! diff -u \
    <(grep -v '^#' "$REFERENCE_CONFIG" | grep -v '^$' | sort) \
    <(grep -v '^#' "$CURRENT_CONFIG" | grep -v '^$' | sort); then
    
    echo "WARNING: Configuration drift detected!"
    
    # Generate detailed report
    echo "Detailed differences:"
    diff -u "$REFERENCE_CONFIG" "$CURRENT_CONFIG" || true
    
    exit 1
else
    echo "SUCCESS: No configuration drift detected"
fi
```

### Configuration Backup

```bash
#!/bin/bash
# backup-config.sh - Backup current configurations

BACKUP_DIR="/backup/kms-configs/$(date +%Y%m%d_%H%M%S)"
CONFIG_DIR="/opt/kms/config"

mkdir -p "$BACKUP_DIR"

# Backup all configuration files
cp -r "$CONFIG_DIR"/* "$BACKUP_DIR/"

# Create metadata
cat > "$BACKUP_DIR/backup-info.txt" << EOF
Backup created: $(date)
Hostname: $(hostname)
KMS version: $(docker image inspect ghcr.io/zama-ai/kms/core-service:latest --format '{{.Config.Labels.version}}' 2>/dev/null || echo "unknown")
Configuration files:
$(ls -la "$CONFIG_DIR")
EOF

echo "SUCCESS: Configuration backup created: $BACKUP_DIR"

# Cleanup old backups (keep last 10)
ls -dt /backup/kms-configs/* | tail -n +11 | xargs rm -rf 2>/dev/null || true
```

## Configuration Checklist

### Pre-Deployment
- [ ] Configuration syntax validated
- [ ] Environment-specific settings verified
- [ ] Security settings configured (TLS, encryption)
- [ ] Storage backend accessibility confirmed
- [ ] Network settings tested
- [ ] Threshold parameters validated (if applicable)
- [ ] Telemetry endpoints configured

### Security Review
- [ ] No sensitive data in plaintext
- [ ] Proper file permissions set (600)
- [ ] TLS certificates valid and not expired
- [ ] Storage encryption enabled
- [ ] Network access properly restricted
- [ ] Audit logging configured

### Operational Readiness
- [ ] Monitoring and alerting configured
- [ ] Backup procedures tested
- [ ] Configuration management automation in place
- [ ] Rollback procedures documented
- [ ] Team access and permissions configured

### Post-Deployment
- [ ] Configuration validation with live service
- [ ] Health checks passing
- [ ] Performance metrics within expected ranges
- [ ] Security scan completed
- [ ] Documentation updated

---

## Related Documentation

- [Production Deployment](production-deployment.md) - Deployment procedures and best practices
- [Monitoring Basics](monitoring-basics.md) - Monitoring and health check procedures
- [Security Checklist](advanced/security.md) - Security hardening and compliance
- [Troubleshooting Guide](advanced/troubleshooting.md) - Configuration-related issue resolution
