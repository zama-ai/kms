# KMS Core Client Docker Image

This Docker image contains the KMS Core Client and Health Check tools for interacting with Zama KMS deployments.

## Image Contents

The image includes two main tools:
- **kms-core-client**: Main client for KMS operations (key generation, encryption, decryption)
- **kms-health-check**: Health monitoring and configuration validation tool

## Security Features

Following Chainguard best practices:
- Based on `cgr.dev/chainguard/glibc-dynamic:latest-dev` for minimal attack surface
- Non-root user execution (uid: 10003, gid: 10002)
- Minimal runtime dependencies (only essential libraries)
- Multi-stage build to exclude build artifacts from final image

## Building the Image

```bash
# Build production image
docker build -t kms-core-client:latest \
  --target prod \
  -f docker/core-client/Dockerfile .

# Build development image with additional tools
docker build -t kms-core-client:dev \
  --target dev \
  -f docker/core-client/Dockerfile .
```

## Running the Container

### KMS Core Client Operations

```bash
# Run core client with config file
docker run -v /path/to/config:/config \
  kms-core-client:latest \
  kms-core-client --config /config/client.toml

# Interactive shell for debugging
docker run -it --entrypoint /bin/sh kms-core-client:latest
```

### Health Check Operations

```bash
# Check live KMS instance health
docker run --network host \
  kms-core-client:latest \
  kms-health-check live --endpoint localhost:50100

# Validate KMS server configuration file (e.g., compose_1.toml, compose_centralized.toml)
# This validates if the KMS server config is correct
docker run -v ./core/service/config:/config \
  kms-core-client:latest \
  kms-health-check config --file /config/compose_1.toml

# Check live KMS instance with JSON output
# No config file needed - just checks the running server
docker run --network host \
  kms-core-client:latest \
  kms-health-check --format json live --endpoint localhost:50100

# Full check: validate KMS server config AND check if running instance matches that config
# The config file is the KMS server's config (helps verify peer connections in threshold mode)
docker run -v ./core/service/config:/config \
  --network host \
  kms-core-client:latest \
  kms-health-check full \
    --config /config/compose_1.toml \
    --endpoint localhost:50100
```

## Docker Compose Integration

### Health Check as Service

```yaml
services:
  kms-health-monitor:
    image: kms-core-client:latest
    command: |
      sh -c "while true; do
        kms-health-check --format json live --endpoint kms-server:50100
        sleep 30
      done"
    depends_on:
      - kms-server
    networks:
      - kms-network
```

### Health Check as Readiness Probe

```yaml
services:
  kms-server:
    image: ghcr.io/zama-ai/kms/core-service:latest
    healthcheck:
      test: ["CMD", "/app/kms-core-client/bin/kms-health-check", "live", "--endpoint", "localhost:50100"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 10s
```

## Kubernetes Integration

### ConfigMap for Health Check Configuration

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: health-check-config
data:
  health-check.toml: |
    connection_timeout_secs = 5
    request_timeout_secs = 10
```

### Deployment with Health Checks

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: kms-client
spec:
  template:
    spec:
      containers:
      - name: kms-client
        image: kms-core-client:latest
        volumeMounts:
        - name: health-config
          mountPath: /config
        livenessProbe:
          exec:
            command:
            - kms-health-check
            - live
            - --endpoint
            - localhost:50100
          periodSeconds: 30
          timeoutSeconds: 10
        readinessProbe:
          exec:
            command:
            - kms-health-check
            - live
            - --endpoint
            - localhost:50100
            - --health-config
            - /config/health-check.toml
          periodSeconds: 10
          timeoutSeconds: 5
      volumes:
      - name: health-config
        configMap:
          name: health-check-config
```

### CronJob for Periodic Health Reports

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: kms-health-report
spec:
  schedule: "*/5 * * * *"  # Every 5 minutes
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: health-check
            image: kms-core-client:latest
            command:
            - sh
            - -c
            - |
              kms-health-check --format json full \
                --config /config/kms.toml \
                --endpoint kms-service:50100 > /tmp/health.json
              # Send to monitoring system
              curl -X POST http://monitoring:9090/metrics \
                -H "Content-Type: application/json" \
                -d @/tmp/health.json
            volumeMounts:
            - name: config
              mountPath: /config
          volumes:
          - name: config
            configMap:
              name: kms-config
          restartPolicy: OnFailure
```

## Environment Variables

Both tools support configuration via environment variables:

```bash
# KMS Core Client
export KMS_ENDPOINT=localhost:50100
export KMS_TLS_CERT=/certs/client.crt
export KMS_TLS_KEY=/certs/client.key

# Health Check Tool (note the double underscore)
export HEALTH_CHECK__CONNECTION_TIMEOUT_SECS=10
export HEALTH_CHECK__REQUEST_TIMEOUT_SECS=30

docker run -e KMS_ENDPOINT -e HEALTH_CHECK__CONNECTION_TIMEOUT_SECS \
  kms-core-client:latest \
  kms-health-check live --endpoint $KMS_ENDPOINT
```

## Network Considerations

### Docker Networks

When running in Docker Compose or Swarm:
- Use service names for internal communication: `kms-server:50100`
- The health check tool automatically handles Docker DNS resolution

### Host Network Mode

For checking services on the host:
```bash
docker run --network host kms-core-client:latest \
  kms-health-check live --endpoint localhost:50100
```

### Bridge Network

For custom networks:
```bash
docker network create kms-network
docker run --network kms-network kms-core-client:latest \
  kms-health-check live --endpoint kms-server:50100
```

## Security Best Practices

1. **Non-root execution**: Container runs as non-root user (uid: 10003)
2. **Minimal base image**: Uses Chainguard's hardened base image
3. **Read-only filesystem**: Can be run with read-only root filesystem
   ```bash
   docker run --read-only --tmpfs /tmp \
     kms-core-client:latest \
     kms-health-check live --endpoint localhost:50100
   ```
4. **Resource limits**: Apply CPU and memory limits
   ```bash
   docker run --memory="256m" --cpus="0.5" \
     kms-core-client:latest \
     kms-health-check live --endpoint localhost:50100
   ```

## Troubleshooting

### Connection Issues

If health checks fail with connection errors:
1. Verify network connectivity: `docker exec <container> ping kms-server`
2. Check DNS resolution: `docker exec <container> nslookup kms-server`
3. Verify port accessibility: `docker exec <container> nc -zv kms-server 50100`

### Permission Issues

If encountering permission errors:
1. Ensure volume mounts have correct permissions (uid: 10003)
2. Use `--user root` for debugging (not recommended for production)

### Debugging

Enable verbose logging:
```bash
docker run kms-core-client:latest \
  kms-health-check live --endpoint localhost:50100 -vvv
```

## Exit Codes

- `0`: Success (Optimal or Healthy status)
- `1`: Warning (Degraded or Unhealthy status)
- `2`: Error (Tool execution failure)

Use these exit codes in scripts and CI/CD pipelines:
```bash
#!/bin/bash
docker run kms-core-client:latest \
  kms-health-check live --endpoint localhost:50100
STATUS=$?
if [ $STATUS -eq 0 ]; then
  echo "KMS is healthy"
elif [ $STATUS -eq 1 ]; then
  echo "KMS needs attention"
  # Send alert
else
  echo "Health check failed"
  exit 1
fi
```

## Version Information

Check tool versions:
```bash
docker run kms-core-client:latest kms-core-client --version
docker run kms-core-client:latest kms-health-check --version
```
