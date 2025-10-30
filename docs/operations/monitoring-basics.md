# KMS Party Monitoring Basics

**Essential monitoring setup for your party's KMS node in a 13-party network.**

## Monitoring Overview

Monitor these key areas for your party's node:
- **Your Node Health** - Is your KMS node running and responding?
- **Performance** - Your node's response times and throughput
- **Resources** - Your node's memory, CPU, disk usage
- **Network Connectivity** - Connection to other 12 parties in the network

## Health Check Tool

The `kms-health-check` tool is your primary monitoring utility.

### Standard Health Check Commands
```bash
# 1. Quick health check of your node
kubectl exec -n kms-threshold kms-core-${PARTY_ID} -- \
  kms-health-check live --endpoint localhost:50100

# 2. Check connectivity to other parties (after network setup)
kubectl exec -n kms-threshold kms-core-${PARTY_ID} -- \
  nc -zv party1-external.kms-threshold.svc.cluster.local 50001

# 3. JSON output for automation
kubectl exec -n kms-threshold kms-core-${PARTY_ID} -- \
  kms-health-check --format json live --endpoint localhost:50100

# 4. Resource usage check
kubectl top pods -n kms-threshold
kubectl describe pod kms-core-${PARTY_ID} -n kms-threshold | grep -A 5 "Limits\|Requests"
```

### Health Status Levels
| Status | Description | Action |
|--------|-------------|--------|
| **Optimal** | All systems normal | Continue monitoring |
| **Healthy** | Minor issues, still operational | Investigate warnings |
| **Degraded** | Reduced functionality | Address issues soon |
| **Unhealthy** | Critical problems | Immediate action required |

### Example Output
```
[KMS HEALTH CHECK REPORT]
==================================================

[OK] Overall Status: Optimal

[CONFIG]:
  [OK] Valid threshold config
  [OK] Storage: File(FileStorage { path: "./keys" })

[CORE SERVICE CONNECTIVITY]:
  [OK] Reachable (latency: 2ms)

[KEY MATERIAL]:
  [OK] FHE Keys: 1
  [OK] CRS: 0
  [OK] Preprocessing: 1

[PEER STATUS] (Threshold):
  3 of 3 peers reachable
  [OK] Party 1 @ kms-node1.example.com (15ms)
  [OK] Party 2 @ kms-node2.example.com (17ms)
  [OK] Party 4 @ kms-node4.example.com (19ms)
==================================================
```

## Key Metrics

### Service Metrics (Production Port 9646)
```bash
# Check metrics endpoint (from within Kubernetes cluster)
kubectl exec -n kms-threshold kms-core-${PARTY_ID} -- \
  curl -s http://localhost:9646/metrics | grep kms_

# Key metrics to watch
kubectl exec -n kms-threshold kms-core-${PARTY_ID} -- \
  curl -s http://localhost:9646/metrics | grep -E "(kms_health_status|kms_peers_reachable|kms_request_duration)"

# For development/Docker deployments, metrics may be on different ports
# Centralized: 9646, Multi-party testing: 9646 (same for all)
```

### System Metrics
```bash
# Kubernetes production deployment
kubectl top pods -n kms-threshold
kubectl top nodes

# For Docker development deployments only
docker stats --no-stream
free -h
df -h

# Network connections (production ports)
netstat -tlnp | grep -E "(50100|50001|9646)"
```

## 🔔 Basic Alerting

### Simple Monitoring Script
```bash
#!/bin/bash
# monitor-kms.sh - Basic KMS monitoring

ENDPOINT="localhost:50100"
CONFIG_FILE="/opt/kms/config/config.toml"
ALERT_EMAIL="ops@example.com"
LOG_FILE="/var/log/kms-monitor.log"

log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

check_health() {
    if ! kms-health-check live --endpoint "$ENDPOINT" >/dev/null 2>&1; then
        log_message "ALERT: KMS health check failed"
        echo "KMS health check failed on $(hostname)" | mail -s "KMS Alert" "$ALERT_EMAIL"
        return 1
    fi
    return 0
}

check_resources() {
    # Check memory usage (alert if >80%)
    MEM_USAGE=$(free | grep Mem | awk '{printf "%.0f", $3/$2 * 100.0}')
    if [ "$MEM_USAGE" -gt 80 ]; then
        log_message "ALERT: High memory usage: ${MEM_USAGE}%"
        echo "High memory usage: ${MEM_USAGE}% on $(hostname)" | mail -s "KMS Memory Alert" "$ALERT_EMAIL"
    fi
    
    # Check disk usage (alert if >85%)
    DISK_USAGE=$(df / | tail -1 | awk '{print $5}' | sed 's/%//')
    if [ "$DISK_USAGE" -gt 85 ]; then
        log_message "ALERT: High disk usage: ${DISK_USAGE}%"
        echo "High disk usage: ${DISK_USAGE}% on $(hostname)" | mail -s "KMS Disk Alert" "$ALERT_EMAIL"
    fi
}

# Run checks
if check_health && check_resources; then
    log_message "INFO: All checks passed"
else
    log_message "ERROR: Some checks failed"
fi
```

### Cron Setup
```bash
# Add to crontab (check every 5 minutes)
*/5 * * * * /opt/kms/scripts/monitor-kms.sh

# View cron logs
tail -f /var/log/kms-monitor.log
```

## Prometheus Setup (Optional)

### Basic Prometheus Config
```yaml
# prometheus.yml
global:
  scrape_interval: 30s

scrape_configs:
  - job_name: 'kms'
    static_configs:
      - targets: ['localhost:9646']
    metrics_path: /metrics
    scrape_interval: 30s
```

### Key Alerting Rules
```yaml
# kms-alerts.yml
groups:
- name: kms-basic
  rules:
  - alert: KMSDown
    expr: up{job="kms"} == 0
    for: 1m
    labels:
      severity: critical
    annotations:
      summary: "KMS service is down"
  
  - alert: KMSHighMemory
    expr: kms_memory_usage_percent > 80
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "KMS high memory usage: {{ $value }}%"
  
  - alert: KMSPeerDown
    expr: kms_peers_reachable < kms_threshold_required + 1
    for: 2m
    labels:
      severity: critical
    annotations:
      summary: "KMS insufficient peers: {{ $value }} reachable"
```

### Docker Compose Integration (Development Only)
```yaml
# docker-compose.yml - For development/testing environments
services:
  kms-server:
    image: ghcr.io/zama-ai/kms/core-service:latest
    ports:
      - "50100:50100"  # gRPC client port (production standard)
      - "9646:9646"    # Metrics port (production standard)
      # Note: P2P port 50001 not exposed for single-node development
    # ... other config

  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"    # Prometheus web UI (development)
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - ./kms-alerts.yml:/etc/prometheus/kms-alerts.yml:ro
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--web.enable-lifecycle'
```

## Container Monitoring

### Docker Health Checks
```yaml
# In docker-compose.yml
services:
  kms-server:
    healthcheck:
      test: ["CMD", "kms-health-check", "live", "--endpoint", "localhost:50100"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 60s
```

### Container Status Monitoring
```bash
#!/bin/bash
# check-containers.sh

# Check container status
CONTAINER_STATUS=$(docker inspect --format='{{.State.Status}}' kms-server 2>/dev/null)

if [ "$CONTAINER_STATUS" != "running" ]; then
    echo "ALERT: KMS container not running (status: $CONTAINER_STATUS)"
    # Restart container
    docker-compose restart kms-server
fi

### Container Health Checks (Development Only)
```yaml
# In docker-compose.yml - for development environments
services:
  kms-server:
    healthcheck:
      test: ["CMD", "kms-health-check", "live", "--endpoint", "localhost:50100"]
      interval: 30s
      timeout: 10s
      retries: 3
```

### Kubernetes Health Checks (Production)
```yaml
# Production Kubernetes StatefulSet uses gRPC probes (port 50100)
readinessProbe:
  grpc:
    port: 50100  # Production gRPC client port
  failureThreshold: 30
  initialDelaySeconds: 10
  periodSeconds: 5

startupProbe:
  grpc:
    port: 50100  # Production gRPC client port
  failureThreshold: 10
  initialDelaySeconds: 10
  periodSeconds: 5

# Alternative: exec-based health check
# readinessProbe:
#   exec:
#     command: ["/app/kms-health-check", "live", "--endpoint", "localhost:50100"]
```

### Service Monitor (Prometheus Operator)
```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: kms-metrics
  namespace: kms
spec:
  selector:
    matchLabels:
      app: kms
  endpoints:
  - port: metrics
    interval: 30s
    path: /metrics
```

## 📱 Notification Setup

### Slack Notifications
```bash
#!/bin/bash
# slack-notify.sh

WEBHOOK_URL="https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK"
MESSAGE="$1"
CHANNEL="#kms-alerts"

curl -X POST -H 'Content-type: application/json' \
    --data "{\"channel\":\"$CHANNEL\",\"text\":\"$MESSAGE\"}" \
    "$WEBHOOK_URL"
```

### Email Alerts
```bash
# Install mail utility
sudo apt-get install mailutils

# Configure in monitoring script
echo "KMS Alert: $MESSAGE" | mail -s "KMS Alert" ops@example.com
```

## Monitoring Checklist

### Daily Checks
- [ ] Service health status is Optimal/Healthy
- [ ] All threshold peers reachable (if applicable)
- [ ] Memory usage < 80%
- [ ] Disk usage < 85%
- [ ] No critical errors in logs

### Weekly Checks
- [ ] Review performance trends
- [ ] Check log rotation and cleanup
- [ ] Verify backup procedures
- [ ] Update monitoring thresholds if needed

### Monthly Checks
- [ ] Review and update alerting rules
- [ ] Performance benchmarking
- [ ] Disaster recovery testing
- [ ] Documentation updates

## Alert Response

### When Alerts Fire
1. **Acknowledge** - Confirm you received the alert
2. **Assess** - Check current system status
3. **Act** - Apply appropriate fix from [quick-reference.md](quick-reference.md)
4. **Monitor** - Verify fix and watch for recurrence
5. **Document** - Record incident and resolution

### Escalation Path
- **Level 1**: Restart services, basic troubleshooting
- **Level 2**: Configuration changes, resource scaling
- **Level 3**: Contact development team for cryptographic issues

---

**Next Steps:**
- Emergency procedures: [quick-reference.md](quick-reference.md)
- Advanced monitoring: [advanced/metrics.md](advanced/metrics.md)
- Troubleshooting: [advanced/troubleshooting.md](advanced/troubleshooting.md)
