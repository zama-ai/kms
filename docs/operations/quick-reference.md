# KMS Party Operations Quick Reference

**Emergency fixes and essential commands for your party's KMS node.**

## Emergency Fixes

### Service Down
```bash
# Check StatefulSet status
kubectl get statefulset kms-core -n kms-threshold
kubectl get pods -n kms-threshold -l app=kms-core

# Restart StatefulSet
kubectl rollout restart statefulset/kms-core -n kms-threshold

# Health check
kubectl exec -n kms-threshold kms-core-${PARTY_ID} -- \
  kms-health-check live --endpoint localhost:50100
```

### Out of Memory (OOMKilled)
```bash
# Check pod resource usage
kubectl top pods -n kms-threshold
kubectl describe pod kms-core-${PARTY_ID} -n kms-threshold | grep -A 5 "Last State"

# Increase memory limits in Helm values
helm upgrade kms-party-${PARTY_ID} . \
  --set kmsCore.resources.limits.memory=32Gi \
  --wait
```

### PRSS Setup Missing (Threshold)
```bash
# Enable PRSS initialization via Helm
helm upgrade kms-party-${PARTY_ID} . \
  --set kmsInit.enabled=true \
  --wait

# Check PRSS initialization logs
kubectl logs -n kms-threshold job/kms-party-${PARTY_ID}-threshold-init

# Verify PRSS files in S3
kubectl exec -n kms-threshold kms-core-${PARTY_ID} -- \
  aws s3 ls s3://zama-kms-party${PARTY_ID}-private/PRIV-p${PARTY_ID}/PrssSetup/
```

### Configuration Error: enable_sys_metrics
```bash
# ERROR: "unknown field `enable_sys_metrics`"
# CAUSE: Deprecated field in telemetry configuration

# Remove from all config files:
sed -i '/enable_sys_metrics/d' config.toml

# Or update Helm values to remove:
helm upgrade kms-party-${PARTY_ID} . \
  --values values-party${PARTY_ID}.yaml \
  --wait
```

### Connection Refused
```bash
# Check service and pod status
kubectl get svc,pods -n kms-threshold -l app=kms-core

# Test connectivity from within cluster
kubectl exec -n kms-threshold kms-core-${PARTY_ID} -- \
  kms-health-check live --endpoint localhost:50100

# Check inter-party connectivity
kubectl exec -n kms-threshold kms-core-${PARTY_ID} -- \
  nc -zv party2-external.kms-threshold.svc.cluster.local 50001
```

### Configuration Errors
```bash
# Check your party's ConfigMap content
kubectl get configmap -n kms-threshold mpc-party-${PARTY_ID} -o yaml

# Validate your Helm values
helm get values kms-party-${PARTY_ID} -n kms-threshold

```

## Essential Diagnostics

### Health Checks

> **Complete Health Check Commands**: See [Monitoring Guide](monitoring-basics.md#standard-health-check-commands) for all standard health check procedures.

### Emergency Health Check
```bash
# Quick status check
kubectl get pods -n kms-threshold -l app=kms-core
kubectl exec -n kms-threshold kms-core-${PARTY_ID} -- \
  kms-health-check live --endpoint localhost:50100
```

### Service Status
```bash
# Pod and StatefulSet status
kubectl get statefulset,pods -n kms-threshold -l app=kms-core
kubectl logs -n kms-threshold kms-core-${PARTY_ID} --tail 50

# Events and troubleshooting
kubectl get events -n kms-threshold --sort-by='.lastTimestamp'
```

### Network Diagnostics
```bash
# Service connectivity within your cluster
kubectl exec -n kms-threshold kms-core-${PARTY_ID} -- \
  nc -zv localhost 50100

# Inter-party connectivity (to other parties in 13-party network)
kubectl exec -n kms-threshold kms-core-${PARTY_ID} -- \
  nc -zv party1-external.kms-threshold.svc.cluster.local 50001

# Check service discovery
kubectl get svc,endpoints -n kms-threshold
```

## Critical Monitoring Alerts

| Alert Condition | Quick Check | Action |
|----------------|-------------|---------|
| **Pod CrashLooping** | `kubectl get pods -n kms-threshold` | Check logs, restart StatefulSet |
| **Memory > 80%** | `kubectl top pods -n kms-threshold` | Increase memory limits |
| **Storage > 85%** | `kubectl exec kms-core-${PARTY_ID} -- df -h` | Expand PVC or cleanup |
| **Health != Optimal** | See [Monitoring Guide](monitoring-basics.md) | Follow health check procedures |

## Essential Configuration

> **Complete Configuration**: See [Configuration Guide](configuration.md) for detailed Helm values and configuration patterns.

### Quick Deployment Commands
```bash
# Deploy your party's KMS using Helm
helm install kms-party-${PARTY_ID} ./charts/kms-core \
  --namespace kms-threshold \
  --create-namespace \
  --values values-party${PARTY_ID}.yaml \
  --wait --timeout=10m
```

### Post-Deployment Verification
```bash
# Check deployment status
kubectl get statefulset,pods -n kms-threshold

# Verify health (see monitoring guide for complete procedures)
kubectl exec -n kms-threshold kms-core-${PARTY_ID} -- \
  kms-health-check live --endpoint localhost:50100
```

## Troubleshooting Checklist

When issues occur:

1. **Identify**
   - [ ] Note exact error message
   - [ ] Check when issue started
   - [ ] Identify affected operations

2. **Quick Check**
   - [ ] Follow [Emergency Health Check](#emergency-health-check) above
   - [ ] Check `kubectl get pods -n kms-threshold`
   - [ ] Review logs: `kubectl logs -n kms-threshold kms-core-${PARTY_ID} --tail 50`

3. **Apply Fix**
   - [ ] Use appropriate solution from emergency fixes above
   - [ ] Test with health check tool
   - [ ] Monitor for 5-10 minutes

4. **Document**
   - [ ] Record issue and solution
   - [ ] Update monitoring if needed

5. **Escalate If**
   - [ ] Issue persists after fixes
   - [ ] Cryptographic errors occur
   - [ ] Data corruption suspected

## Quick Links

- **Full Documentation**: [README.md](README.md)
- **Production Deployment**: [production-deployment.md](production-deployment.md)
- **Monitoring Setup**: [monitoring-basics.md](monitoring-basics.md)
- **Advanced Topics**: [advanced/](advanced/)

---

**Tip**: Bookmark this page for quick access during incidents. Most operational issues can be resolved with the commands above.
