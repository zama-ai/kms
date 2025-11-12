# Emergency Procedures

**Quick fixes and emergency commands for your party's KMS node.**

## Emergency Fixes

> **Detailed Solutions**: See [Common Errors Guide](advanced/common-errors.md) for comprehensive troubleshooting procedures.

### Quick Emergency Commands
```bash
# Service status check
kubectl get pods -n <NAMESPACE> -l app=kms-core
kubectl exec -n <NAMESPACE> kms-core-<PARTY_ID> -- \
  kms-health-check live --endpoint localhost:<GRPC_PORT>

# Restart service
kubectl rollout restart statefulset/kms-core -n <NAMESPACE>

# Check recent events
kubectl get events -n <NAMESPACE> --sort-by='.lastTimestamp' | tail -10
```

### Common Issues Quick Reference
- **OOMKilled**: Increase memory limits to 32Gi minimum
- **PRSS Missing**: Enable PRSS initialization in Helm values, verify with `kms-health-check`
- **enable_sys_metrics Error**: Remove deprecated field from configuration
- **Connection Refused**: Check service status and restart if needed
- **Key Material Issues**: Use `kms-health-check live` to verify key availability and storage

**Health Check Tool**: Use `kms-health-check live --endpoint localhost:<GRPC_PORT>` to verify:
- Service connectivity and latency
- Key material availability (FHE keys, CRS, preprocessing)
- Peer connectivity (threshold mode)
- Storage configuration

> **Port Configuration**: Replace `<GRPC_PORT>` with your configured gRPC port:
> - **Default**: 50100
> - **Find configured port**: Check `listen_port` in your `[service]` configuration section
> - **Kubernetes**: Check your Helm values or service configuration

**For detailed solutions**: See [Common Errors Guide](advanced/common-errors.md)

## Essential Diagnostics

### Health Checks

> **Complete Health Check Commands**: See [Monitoring Guide](monitoring.md#standard-health-check-commands) for all standard health check procedures.

### Emergency Health Check
```bash
# Quick status check
kubectl get pods -n <NAMESPACE> -l app=kms-core
kubectl exec -n <NAMESPACE> kms-core-<PARTY_ID> -- \
  kms-health-check live --endpoint localhost:<GRPC_PORT>
```

### Service Status
**Check Service Health**:
- Use `kubectl get pods` and `kubectl logs` for basic status
- Use `kms-health-check` tool for comprehensive health verification
- See [Monitoring Guide](monitoring.md) for detailed procedures

### Network Diagnostics
**Connectivity Testing**:
- Test local service connectivity and inter-party connections
- Verify service discovery and endpoints
- See [Troubleshooting Guide](advanced/troubleshooting.md) for network diagnostics

## Critical Monitoring Alerts

| Alert Condition | Quick Check | Action |
|----------------|-------------|---------|
| **Pod CrashLooping** | `kubectl get pods -n <NAMESPACE>` | Check logs, restart StatefulSet |
| **Memory > 80%** | `kubectl top pods -n <NAMESPACE>` | Increase memory limits |
| **Storage > 85%** | `kubectl exec kms-core-<PARTY_ID> -- df -h` | Expand PVC or cleanup |
| **Health != Optimal** | See [Monitoring Guide](monitoring.md) | Follow health check procedures |

## Essential Configuration

> **Complete Configuration**: See [Configuration Guide](configuration.md) for detailed Helm values and configuration patterns.

### Quick Deployment Commands
**Deployment**:
- Use Helm charts (`charts/kms-core/`) for application deployment
- See [Configuration Guide](configuration.md) for Helm values and deployment procedures

### Post-Deployment Verification
**Verification**:
- Check deployment status with `kubectl get pods`
- Verify health with `kms-health-check` tool
- See [Monitoring Guide](monitoring.md) for complete verification procedures

## Quick Links

- **Full Documentation**: [README.md](README.md)
- **Production Deployment**: [production-deployment.md](production-deployment.md)
- **Monitoring Setup**: [monitoring.md](monitoring.md)
- **Advanced Topics**: [advanced/](advanced/)

---

**Tip**: Bookmark this page for quick access during incidents. Most operational issues can be resolved with the commands above.
