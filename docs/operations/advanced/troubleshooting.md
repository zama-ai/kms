# KMS Advanced Troubleshooting Guide

**Systematic troubleshooting procedures for complex KMS operational issues in 13-party threshold deployments.**

> **Quick Fixes**: For immediate solutions to common problems, see [Common Errors](common-errors.md) and [Emergency Procedures](../emergency-procedures.md).

## Initial Diagnosis

Start with these commands to gather essential information:

```bash
# System overview
kubectl get pods,svc,pvc -n <NAMESPACE> -o wide
kubectl top pods -n <NAMESPACE>

# Health check (may not be available in Chainguard enclave containers)
# Use external health check or test endpoints directly
kubectl port-forward -n <NAMESPACE> <POD_NAME> 9646:9646 &
curl -f http://localhost:9646/health    # Health status
curl -f http://localhost:9646/version   # Version of the KMS running
curl -f http://localhost:9646/config    # The configuration used

# Recent logs and events - replace <POD_NAME> with actual pod name
kubectl logs -n <NAMESPACE> <POD_NAME> --tail=100 | grep -E "(ERROR|FATAL|PANIC|WARN)"
kubectl get events -n <NAMESPACE> --sort-by='.lastTimestamp'
```

> **Note**: Replace `<NAMESPACE>` and `<POD_NAME>` with your actual values. Get pod names with `kubectl get pods -n <NAMESPACE>`.

> **Standard Health Checks**: See [Monitoring Guide](../monitoring.md) for complete monitoring procedures.

## Issue Classification & Resolution

### Service Startup Issues

**Symptoms:**
- Pod in CrashLoopBackOff state
- StatefulSet not ready
- Port binding errors

> **Quick Solutions**: See [Common Errors](common-errors.md) for immediate fixes to startup issues.

**Additional Checks:**
```bash
# Detailed pod information
kubectl describe pod -n <NAMESPACE> <POD_NAME>
```

**Common Fixes:**
- Update Helm values for configuration errors
- Increase resource limits if OOMKilled
- Check storage class and PVC availability

---

### Connectivity Issues

**Symptoms:**
- Connection refused errors
- Timeout errors
- Intermittent connectivity

**Additional Checks:**
```bash
# Test port connectivity (using port-forward for Chainguard images)
kubectl port-forward -n <NAMESPACE> <POD_NAME> <LOCAL_PORT>:<GRPC_PORT> &
curl -f http://localhost:<LOCAL_PORT>/health
```

**Common Fixes:**
- Verify service is listening on correct ports
- Check DNS resolution for external services
- Review firewall/security group rules

---

### Performance Issues

**Symptoms:**
- Slow response times
- High CPU/memory usage
- Request timeouts

**Additional Checks:**
```bash
# Check resource limits and constraints
kubectl describe pod -n <NAMESPACE> <POD_NAME> | grep -A 5 "Limits\|Requests"
```

**Common Fixes:**
- Increase CPU/memory limits if hitting constraints
- Check metrics endpoint for performance patterns
- Review configuration for optimization opportunities

---

### 13-Party Threshold Network Issues

**Symptoms:**
- Peer connectivity failures (< 5 parties reachable)
- Session synchronization issues
- PRSS setup problems

> **Network Requirements**: Your party needs connectivity to at least 4 other parties for t=4 threshold operations.

**Additional Checks:**
```bash
# Test connectivity to other parties
kubectl exec -n <NAMESPACE> <POD_NAME> -- nc -zv <PEER_HOST> <P2P_PORT>

# Check PRSS initialization
kubectl logs -n <NAMESPACE> job/<INIT_JOB_NAME>
```

**Common Fixes:**
- Coordinate with other parties to ensure nodes are online
- Verify network connectivity between parties
- Check PRSS initialization completed successfully

---

### Storage Backend Issues

**Symptoms:**
- Key material not found
- Storage access errors
- Backup/restore failures

**Additional Checks:**
```bash
# Inspect storage (Chainguard images have limited tools)
kubectl describe pod -n <NAMESPACE> <POD_NAME> | grep -A 10 "Mounts:"
kubectl get pvc -n <NAMESPACE>
```

**Common Fixes:**
- Verify storage backend configuration and credentials
- Check file permissions and available disk space
- Use health check tool for comprehensive storage verification

---

### Public Storage Verification Failures at Startup

Every node verifies its public storage against private storage during startup and refuses to
serve if they disagree. Public storage can drift out of a consistent state — a misconfigured
bucket or prefix pointing at the wrong material, or a crash part-way through a non-atomic write
leaving an entry missing, truncated, or stale. Private storage holds the digests and signatures
describing what should be published, so it is the reference.

**Symptoms:** the pod exits during startup with one of these log lines, before any request is
served:

| Log line | Meaning |
|---|---|
| `missing or unreadable public material <type> for id=<id>` | Private storage expects a published object that public storage does not have, or it cannot be read. |
| `Server key digest mismatch` / `Public key digest mismatch` / `Compressed xof keyset digest mismatch` / `CRS digest mismatch` | The published bytes do not hash to the digest recorded in private storage. |
| `Result metadata signature invalid` | The digest recorded in *private* storage does not match its own signature, i.e. the private metadata itself is corrupt. |
| `Verification key/address in public storage does not match the private signing key`  | The published `VerfKey` / `VerfAddress` is not the one derived from this node's signing key. |

**Common Fixes:**
- Confirm the node is pointed at the correct public storage bucket and prefix.
- Restore the named object from a known-good copy, either from a backup or from another party.
- Seek the Zama team if any of these issues occur since resolving most of these will
  require manual intervention.

---

### Key Management Issues

**Symptoms:**
- Key generation failures
- Key validation errors
- Cryptographic operation failures

**Additional Checks:**
```bash
# Test gRPC connectivity (reflection API not enabled in production)
kubectl port-forward -n <NAMESPACE> <POD_NAME> 50100:50100 &
# Test if gRPC port is responding
nc -zv localhost 50100 || curl -v http://localhost:50100 2>&1 | grep -i "grpc\|http2"

# Check metrics endpoint for key material status
kubectl port-forward -n <NAMESPACE> <POD_NAME> 9646:9646 &
curl -s http://localhost:9646/metrics | grep -i "key\|material"
```

**Common Fixes:**
- Test endpoints via port-forward to verify functionality
- Check logs for key material loading errors
- Verify cryptographic library compatibility in deployment

---

## Advanced Diagnostics

For deeper analysis when standard troubleshooting doesn't resolve issues:

> **Note**: Chainguard images are distroless and don't include debugging tools like `ss`, `netstat`, `ps`, `bash`, `kms-health-check`, or `grpcurl`.

```bash
# Container debugging (limited in Chainguard images)
kubectl logs -n <NAMESPACE> <POD_NAME> --timestamps

# Network analysis (use kubectl port-forward instead)
kubectl port-forward -n <NAMESPACE> <POD_NAME> <LOCAL_PORT>:<GRPC_PORT>
# Then test locally: curl http://localhost:<LOCAL_PORT>/health

# Process and memory analysis (use kubectl top instead)
kubectl top pod -n <NAMESPACE> <POD_NAME> --containers
```

## Emergency Procedures

> **Critical Issues**: See [Emergency Procedures](../emergency-procedures.md) for immediate fixes.

### Service Recovery
```bash
# Restart pod
kubectl delete pod -n <NAMESPACE> <POD_NAME>
kubectl get pods -n <NAMESPACE> -w  # Watch restart

# Rollback deployment if needed
helm rollback <RELEASE_NAME> -n <NAMESPACE>
```

## Troubleshooting Checklist

### Quick Assessment
- [ ] Run `kms-health-check` for automated diagnostics
- [ ] Check pod status and recent events  
- [ ] Review logs for error patterns
- [ ] Verify resource usage and limits

### Resolution Steps
- [ ] Apply appropriate fix based on root cause
- [ ] Test the fix thoroughly
- [ ] Monitor for recurrence
- [ ] Document the issue and solution

---

## Related Documentation

- [Common Errors](common-errors.md) - Quick fixes for frequent issues
- [Metrics & Monitoring](metrics.md) - Monitoring tools and procedures
- [Kubernetes Deployment](kubernetes-deployment.md) - Alternative deployment procedures
- [Configuration Management](../configuration.md) - Configuration best practices
