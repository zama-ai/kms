# KMS Monitoring & Metrics

**Comprehensive monitoring setup for your party's KMS node in a 13-party network.**

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
The health check tool reports status in four levels: **Optimal**, **Healthy**, **Degraded**, and **Unhealthy**. See [Health Check Tool Documentation](../../tools/kms-health-check/README.md) for detailed status descriptions and example outputs.

## Key Metrics

**Metrics Access**:
- KMS exposes Prometheus metrics on port <METRICS_PORT> at `/metrics` endpoint (default: 9646)
- Use `kubectl top` for basic resource monitoring in Kubernetes
- See [Metrics Documentation](advanced/metrics.md) for complete metrics reference and monitoring setup

## 🔔 Basic Alerting

**Monitoring Automation**:
- Use `kms-health-check` tool for automated health monitoring
- Configure monitoring frequency based on your operational requirements
- Integrate with your existing alerting infrastructure (Prometheus, Nagios, etc.)
- See [Health Check Tool Documentation](../../tools/kms-health-check/README.md) for automation examples

## Prometheus Integration

**Metrics Collection**:
- KMS exposes Prometheus metrics on port <METRICS_PORT> at `/metrics` endpoint (default: 9646)
- Configure Prometheus to scrape KMS metrics based on your deployment
- See [Metrics Documentation](advanced/metrics.md) for complete setup and alerting guidance

**Alerting**:
- Configure alerts based on KMS-specific metrics and your operational requirements
- See [Prometheus Alerting Documentation](https://prometheus.io/docs/prometheus/latest/configuration/alerting_rules/) for alerting rule configuration

### Docker Compose Integration (Development Only)
**Development Setup**:
- Expose gRPC port (<GRPC_PORT>, default: 50100) and metrics port (<METRICS_PORT>, default: 9646)
- Configure Prometheus to scrape KMS metrics endpoint
- See [Configuration Guide](configuration.md) for Docker setup guidance

## Container Monitoring

### Docker Health Checks
**Development Environments**:
- Use `kms-health-check` tool in Docker healthcheck configuration
- Configure intervals and timeouts based on your requirements
- See Docker documentation for healthcheck configuration options

### Kubernetes Health Checks
**Production Environments**:
- KMS Helm chart includes gRPC-based readiness and startup probes
- Probes use the configured gRPC port for health checking
- Alternative: exec-based probes using `kms-health-check` tool
- See [Kubernetes Probe Documentation](https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/) for configuration options

### Service Monitor Integration

**Prometheus Operator**:
- KMS Helm chart includes ServiceMonitor configuration
- Metrics exposed on port <METRICS_PORT> at `/metrics` endpoint (default: 9646)
- See [Metrics Documentation](advanced/metrics.md) for complete setup

## 📱 Notification Setup

**Alert Notifications**:
- Configure notifications based on your existing alerting infrastructure
- Common integrations: Slack, email, PagerDuty, Microsoft Teams
- See [Prometheus Alertmanager Documentation](https://prometheus.io/docs/alerting/latest/alertmanager/) for configuration examples


## Alert Response

### When Alerts Fire
1. **Acknowledge** - Confirm you received the alert
2. **Assess** - Check current system status
3. **Act** - Apply appropriate fix from [emergency-procedures.md](emergency-procedures.md)
4. **Monitor** - Verify fix and watch for recurrence
5. **Document** - Record incident and resolution

### Escalation Path
- **Level 1**: Restart services, basic troubleshooting
- **Level 2**: Configuration changes, resource scaling
- **Level 3**: Contact development team for cryptographic issues

---

**Next Steps:**
- Emergency procedures: [emergency-procedures.md](emergency-procedures.md)
- Advanced monitoring: [advanced/metrics.md](advanced/metrics.md)
- Troubleshooting: [advanced/troubleshooting.md](advanced/troubleshooting.md)
