# KMS Metrics, Monitoring & Alerting

**Comprehensive monitoring setup with health checks, Prometheus metrics, Grafana dashboards, and alerting rules for production KMS deployments.**

> **Basic Monitoring**: See [Monitoring Basics](../monitoring-basics.md) for standard health check commands and essential monitoring setup.

## Advanced Health Check Configuration

### Custom Health Check Timeouts

Create `health-check.toml` for custom timeouts:

```toml
# Connection timeout in seconds (default: 5)
connection_timeout_secs = 10

# Request timeout in seconds (default: 10)
request_timeout_secs = 30
```

Environment variable overrides:
```bash
# Set custom timeouts via environment
export HEALTH_CHECK__CONNECTION_TIMEOUT_SECS=15
export HEALTH_CHECK__REQUEST_TIMEOUT_SECS=45

kms-health-check live --endpoint localhost:50100
```

### 13-Party Network Health Status

| Status | Description (13-party network, t=4) | Action Required |
|--------|-------------------------------------|-----------------|
| **Optimal** | All 13 parties reachable | Normal operations |
| **Healthy** | 9+ parties reachable | Monitor offline parties |
| **Degraded** | 5-8 parties reachable | Check connectivity issues |
| **Unhealthy** | < 5 parties reachable | Cannot perform threshold operations |

## Actual KMS Metrics

KMS exposes metrics via Prometheus format on the configured metrics endpoint (default: `:9646/metrics`).

### Core Metrics (Actual Implementation)

#### Counters

```prometheus
# Total number of operations processed (tagged by operation type)
kms_operations{operation="keygen_request"} 42
kms_operations{operation="user_decrypt_request"} 1337
kms_operations{operation="public_decrypt_request"} 256
kms_operations{operation="crs_gen_request"} 8
kms_operations{operation="init"} 1

# Total number of operation errors (tagged by operation and error type)
kms_operation_errors{operation="user_decrypt_request",error="invalid_argument"} 5
kms_operation_errors{operation="keygen_request",error="internal_error"} 2

# Network traffic counters
kms_network_rx_bytes 1048576
kms_network_tx_bytes 2097152
```

#### Histograms

```prometheus
# Operation duration in milliseconds
kms_operation_duration_ms_bucket{operation="user_decrypt_request",le="100"} 95
kms_operation_duration_ms_bucket{operation="user_decrypt_request",le="500"} 99
kms_operation_duration_ms_bucket{operation="user_decrypt_request",le="1000"} 100
kms_operation_duration_ms_bucket{operation="user_decrypt_request",le="+Inf"} 100
kms_operation_duration_ms_sum{operation="user_decrypt_request"} 12500
kms_operation_duration_ms_count{operation="user_decrypt_request"} 100

# Payload size in bytes
kms_payload_size_bytes_bucket{operation="user_decrypt_request",le="1024"} 80
kms_payload_size_bytes_bucket{operation="user_decrypt_request",le="10240"} 95
kms_payload_size_bytes_bucket{operation="user_decrypt_request",le="102400"} 100
kms_payload_size_bytes_bucket{operation="user_decrypt_request",le="+Inf"} 100
```

#### Gauges

```prometheus
# CPU load (percentage, averaged over all CPUs)
kms_cpu_load 25.5

# Memory usage in bytes
kms_memory_usage 536870912

# Generic gauge for various measurements
kms_gauge{operation="custom_metric"} 42
```

#### System Metrics (Linux only, when enable_sys_metrics=true)

```prometheus
# Process metrics (via ProcessCollector)
process_cpu_seconds_total 123.45
process_resident_memory_bytes 67108864
process_virtual_memory_bytes 134217728
process_open_fds 128
process_max_fds 4096
```

### Available Operations

Operations tracked in metrics (from `observability/src/metrics_names.rs`):

**Key Generation:**
- `keygen_request`, `keygen_result`
- `insecure_keygen_request`, `insecure_keygen_result`
- `keygen_preproc_request`, `keygen_preproc_result`

**Decryption:**
- `user_decrypt_request`, `user_decrypt_result`
- `public_decrypt_request`, `public_decrypt_result`

**CRS Operations:**
- `crs_gen_request`, `crs_gen_result`
- `insecure_crs_gen_request`, `insecure_crs_gen_result`

**System:**
- `init` (PRSS initialization)
- `system_startup`

### Health Endpoints

```bash
# Metrics endpoint
curl http://localhost:9646/metrics

# Health endpoints
curl http://localhost:9646/health    # Returns "ok"
curl http://localhost:9646/ready     # Readiness check
curl http://localhost:9646/live      # Liveness check
```

## Prometheus Configuration

### Scrape Configuration

```yaml
# prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'kms'
    static_configs:
      - targets: ['localhost:9646']
    scrape_interval: 30s
    metrics_path: /metrics
    
  # For Kubernetes deployment
  - job_name: 'kms-kubernetes'
    kubernetes_sd_configs:
      - role: pod
        namespaces:
          names:
            - kms-threshold
    relabel_configs:
      - source_labels: [__meta_kubernetes_pod_label_app]
        action: keep
        regex: kms-core
      - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_scrape]
        action: keep
        regex: true
      - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_port]
        action: replace
        target_label: __address__
        regex: (.+)
        replacement: ${1}:9646
```

## Alerting Rules (Based on Actual Metrics)

```yaml
# kms-alerts.yml
groups:
- name: kms-critical
  rules:
  
  # High Error Rate
  - alert: KMSHighErrorRate
    expr: |
      (
        rate(kms_operation_errors[5m]) / 
        (rate(kms_operations[5m]) + rate(kms_operation_errors[5m]))
      ) * 100 > 5
    for: 5m
    labels:
      severity: critical
      team: infrastructure
    annotations:
      summary: "KMS error rate is high on {{ $labels.instance }}"
      description: "Error rate is {{ $value }}% over the last 5 minutes"
  
  # High Operation Latency
  - alert: KMSHighLatency
    expr: |
      histogram_quantile(0.95, 
        rate(kms_operation_duration_ms_bucket[5m])
      ) > 5000
    for: 5m
    labels:
      severity: warning
      team: infrastructure
    annotations:
      summary: "KMS operations are slow on {{ $labels.instance }}"
      description: "95th percentile latency is {{ $value }}ms"
  
  # High Memory Usage
  - alert: KMSHighMemoryUsage
    expr: kms_memory_usage > (16 * 1024 * 1024 * 1024)  # 16GB
    for: 10m
    labels:
      severity: warning
      team: infrastructure
    annotations:
      summary: "KMS memory usage is high on {{ $labels.instance }}"
      description: "Memory usage is {{ $value | humanizeBytes }}"
  
  # High CPU Load
  - alert: KMSHighCPULoad
    expr: kms_cpu_load > 80
    for: 10m
    labels:
      severity: warning
      team: infrastructure
    annotations:
      summary: "KMS CPU load is high on {{ $labels.instance }}"
      description: "CPU load is {{ $value }}%"

- name: kms-info
  rules:
  
  # Operation Rate Monitoring
  - alert: KMSLowOperationRate
    expr: rate(kms_operations[5m]) < 0.1
    for: 15m
    labels:
      severity: info
      team: operations
    annotations:
      summary: "KMS operation rate is low on {{ $labels.instance }}"
      description: "Operation rate is {{ $value }} ops/sec"
```

## Grafana Dashboard

### KMS Operations Dashboard

```json
{
  "dashboard": {
    "title": "KMS Operations",
    "panels": [
      {
        "title": "Operation Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(kms_operations[5m])",
            "legendFormat": "{{ operation }}"
          }
        ]
      },
      {
        "title": "Error Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(kms_operation_errors[5m])",
            "legendFormat": "{{ operation }} - {{ error }}"
          }
        ]
      },
      {
        "title": "Operation Latency",
        "type": "graph",
        "targets": [
          {
            "expr": "histogram_quantile(0.50, rate(kms_operation_duration_ms_bucket[5m]))",
            "legendFormat": "50th percentile"
          },
          {
            "expr": "histogram_quantile(0.95, rate(kms_operation_duration_ms_bucket[5m]))",
            "legendFormat": "95th percentile"
          },
          {
            "expr": "histogram_quantile(0.99, rate(kms_operation_duration_ms_bucket[5m]))",
            "legendFormat": "99th percentile"
          }
        ]
      },
      {
        "title": "System Resources",
        "type": "graph",
        "targets": [
          {
            "expr": "kms_cpu_load",
            "legendFormat": "CPU Load %"
          },
          {
            "expr": "kms_memory_usage / (1024*1024*1024)",
            "legendFormat": "Memory Usage GB"
          }
        ]
      },
      {
        "title": "Network Traffic",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(kms_network_rx_bytes[5m])",
            "legendFormat": "RX bytes/sec"
          },
          {
            "expr": "rate(kms_network_tx_bytes[5m])",
            "legendFormat": "TX bytes/sec"
          }
        ]
      }
    ]
  }
}
```

## Configuration

### Enable System Metrics

```toml
# In KMS configuration file
[telemetry]
metrics_bind_address = "0.0.0.0:9646"
enable_sys_metrics = true  # Enables ProcessCollector on Linux
```

### Kubernetes ServiceMonitor

```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: kms-metrics
  namespace: kms-threshold
spec:
  selector:
    matchLabels:
      app: kms-core
  endpoints:
  - port: metrics
    interval: 30s
    path: /metrics
```

## Custom Metrics Collection

### Health Check Metrics Exporter

```bash
#!/bin/bash
# kms-health-exporter.sh - Export health check results as custom metrics

METRICS_PORT="${METRICS_PORT:-9091}"
KMS_ENDPOINT="${KMS_ENDPOINT:-localhost:50100}"
METRICS_FILE="/tmp/kms-health-metrics.prom"

# Function to run health check and export metrics
export_health_metrics() {
    local endpoint="$1"
    local timestamp=$(date +%s)
    
    # Run health check
    if kms-health-check live --endpoint "$endpoint" >/dev/null 2>&1; then
        local status=1
    else
        local status=0
    fi
    
    # Export custom metrics
    cat > "$METRICS_FILE" << EOF
# HELP kms_health_check_status Health check status (1=healthy, 0=unhealthy)
# TYPE kms_health_check_status gauge
kms_health_check_status{endpoint="$endpoint"} $status

# HELP kms_health_check_timestamp Last health check timestamp
# TYPE kms_health_check_timestamp gauge
kms_health_check_timestamp{endpoint="$endpoint"} $timestamp
EOF
}

# Main loop
while true; do
    export_health_metrics "$KMS_ENDPOINT"
    
    # Serve metrics on HTTP
    python3 -m http.server "$METRICS_PORT" --directory /tmp &
    SERVER_PID=$!
    
    sleep 60
    kill $SERVER_PID 2>/dev/null
done
```

## Monitoring Best Practices

### Metric Collection Guidelines

1. **Scrape Intervals**
   - Core KMS metrics: 30 seconds
   - System metrics: 15 seconds  
   - Custom health checks: 60 seconds

2. **Retention Policies**
   - High-resolution (15s): 7 days
   - Medium-resolution (5m): 30 days
   - Low-resolution (1h): 1 year

3. **Alert Thresholds**
   - Error rate: > 5% for 5 minutes
   - Latency: 95th percentile > 5 seconds
   - Memory: > 16GB for 10 minutes
   - CPU: > 80% for 10 minutes

### Dashboard Organization

1. **Overview Dashboard**
   - Operation rates and error rates
   - System resource usage
   - Network traffic

2. **Detailed Operations**
   - Per-operation metrics
   - Latency distributions
   - Error breakdowns

3. **System Health**
   - Resource utilization trends
   - Process metrics (if enabled)
   - Health check status

## Troubleshooting Metrics

### Common Issues

**Missing Metrics:**
```bash
# Check if metrics endpoint is accessible
curl http://localhost:9646/metrics

# Verify telemetry configuration
grep -A 5 "\[telemetry\]" /path/to/config.toml
```

**High Cardinality:**
```bash
# Check metric cardinality
curl -s http://localhost:9646/metrics | grep "^kms_" | wc -l

# Monitor memory usage of Prometheus
curl -s http://prometheus:9090/api/v1/query?query=process_resident_memory_bytes
```

**Alerting Issues:**
```bash
# Test alert rules
promtool query instant http://localhost:9090 'rate(kms_operation_errors[5m]) > 0'

# Check Alertmanager status
curl http://alertmanager:9093/api/v1/status
```

## Related Documentation

- [Monitoring Basics](../monitoring-basics.md) - Essential health check procedures and tools
- [Troubleshooting Guide](troubleshooting.md) - Issue resolution procedures
- [Deployment Guide](deployment.md) - Deployment and configuration
- [Common Errors](common-errors.md) - Quick fixes for frequent issues

---

**Note**: This documentation reflects the actual metrics implementation in KMS. All metric names, endpoints, and configurations are based on the current codebase and are verified to be accurate.
