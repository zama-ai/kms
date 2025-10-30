# Common KMS Errors & Solutions

This guide provides quick solutions for the most frequently encountered KMS operational issues. For systematic troubleshooting, see the [Troubleshooting Guide](troubleshooting.md).

## Critical Errors (Immediate Action Required)

### Out of Memory (OOMKilled)

**Error Messages:**
```bash
dev-kms-core-1-1 exited with code 137
# or
Out of Memory error, OOMKilled
```

**Root Cause:** Insufficient memory allocation for KMS operations.

**Immediate Solution:**
```bash
# Check current memory usage (Kubernetes production)
kubectl top pods -n kms-threshold
kubectl describe pod kms-core-${PARTY_ID} -n kms-threshold | grep -A 5 "Last State"

# Increase memory limits in Helm values
helm upgrade kms-party-${PARTY_ID} . \
  --set kmsCore.resources.limits.memory=32Gi \
  --wait

# For Docker development environments
docker stats
```

**Prevention:**
- Minimum 16Gi RAM for production (32Gi recommended)
- 4Gi RAM minimum for development/testing
- Monitor with `kubectl top pods` or Prometheus metrics

---

### No Space Left on Device

**Error Message:**
```bash
No space left on device
```

**Immediate Solution:**
```bash
# Check disk usage (Kubernetes production)
kubectl exec -n kms-threshold kms-core-${PARTY_ID} -- df -h
kubectl get pvc -n kms-threshold  # Check persistent volume claims

# Clean up if using Docker for development
docker system prune -a --volumes

# For Kubernetes: Increase PVC size or add storage
kubectl patch pvc kms-data-kms-core-${PARTY_ID} -n kms-threshold \
  -p '{"spec":{"resources":{"requests":{"storage":"200Gi"}}}}'
```

**Prevention:**
- Monitor disk usage regularly
- Set up disk space alerts at 80% capacity
- Plan for key material and log storage growth

---

### PRSS Setup Missing (Threshold KMS)

**Error Messages:**
```bash
No PRSS setup exists
# or
WARN kms_lib::threshold::threshold_kms: failed to read PRSS from file with error: No such file or directory (os error 2)
INFO kms_lib::threshold::threshold_kms: Initializing threshold KMS server without PRSS Setup, remember to call the init GRPC endpoint
```

**Root Cause:** Threshold KMS requires PRSS (Pseudo-Random Secret Sharing) initialization across all parties.

**Immediate Solution:**
```bash
# Initialize PRSS for 13-party threshold network
# (Network coordinator triggers this across all parties)
helm upgrade kms-party-${PARTY_ID} . \
  --set kmsInit.enabled=true \
  --wait

# Monitor PRSS initialization
kubectl logs -n kms-threshold job/kms-party-${PARTY_ID}-threshold-init
```

**File Location Check:**
```bash
# PRSS files should exist at:
ls -la keys/PRIV-p*/PrssSetup/000*0001
```

**Prevention:**
- Ensure PRSS initialization is part of deployment automation
- Verify all threshold parties are online during initialization
- Backup PRSS setup files after successful initialization

---

## Service Errors

### Connection Refused / Timeout

**Error Messages:**
```bash
Connection refused
# or
Failed to connect to WebSocket provider: JsonRpcClientError(InternalError(Io(Os { code: 61, kind: ConnectionRefused, message: "Connection refused" })))
```

**Diagnosis Steps:**
```bash
# 1. Check if your KMS pod is running (Kubernetes production)
kubectl get pods -n kms-threshold -l app=kms-core
kubectl describe pod kms-core-${PARTY_ID} -n kms-threshold

# 2. Test connectivity
kubectl exec -n kms-threshold kms-core-${PARTY_ID} -- \
  kms-health-check live --endpoint localhost:50100

# For Docker development environments
docker ps | grep kms
curl -f http://localhost:50100/health
```

**Common Solutions:**
- Verify pod is running: `kubectl get pods -n kms-threshold`
- Check service status: `kubectl get svc -n kms-threshold`
- Restart if needed: `kubectl rollout restart statefulset/kms-core -n kms-threshold`
- For Docker development: `docker-compose up -d`

---

### Unknown Session ID (Threshold KMS)

**Error Message:**
```bash
ERROR distributed_decryption::networking::grpc: msg="unknown session id SessionId(...) for from sender Identity(...) (round 1)"
```

**Root Cause:** Timing issues between threshold parties during protocol execution.

**Solutions:**
1. **Temporary Fix:** Wait and retry - the protocol includes automatic retry mechanisms
2. **Persistent Issues:** 
   ```bash
   # Check party synchronization
   kms-health-check full --config threshold-config.toml --endpoint localhost:50100
   
   # Verify your party health and connectivity to others
   kubectl exec -n kms-threshold kms-core-${PARTY_ID} -- \
     kms-health-check live --endpoint localhost:50100
   
   # Test connectivity to other parties (after network setup)
   kubectl exec -n kms-threshold kms-core-${PARTY_ID} -- \
     nc -zv party1-external.kms-threshold.svc.cluster.local 50001
   ```

**Prevention:**
- Ensure stable network connectivity between threshold parties
- Monitor party health and restart lagging nodes
- Consider increasing timeout values in high-latency environments

---

### TFHE Version Mismatch

**Error Messages:**
```bash
assertion `left == right` failed
  left: LweSize(1281)
 right: LweSize(1025)
# or
We can't deserialize our own validated sks key: DeserializationError("invalid value: integer `1`, expected variant index 0 <= i < 1")
```

**Root Cause:** Incompatible TFHE-rs versions between components or using keys from different versions.

**Solutions:**
```bash
# 1. Check TFHE versions in use
grep tfhe Cargo.toml

# 2. Regenerate keys with current version
rm -rf keys/
# Run key generation process

# 3. For coprocessor version mismatch, update image:
# In docker-compose.yaml:
# coproc:
#   image: ghcr.io/zama-ai/fhevm-coprocessor:v0.1.0-3  # Uses tfhe-rs 0.9
```

**Prevention:**
- Use consistent TFHE-rs versions across all components
- Test key compatibility after version upgrades
- Backup keys before version changes

---

## Configuration Errors

### Invalid Configuration

**Error Message:**
```bash
Config validation failed: ...
```

**Diagnosis:**
```bash
# Validate configuration
kms-health-check config --file config.toml

# Check specific validation errors
cargo run --bin kms-server -- --config config.toml --dry-run
```

**Common Issues:**
- **Threshold too high:** For 13-party network, threshold=4 requires minimum 5 parties online
- **Invalid addresses:** Check IP addresses and ports in peer configuration
- **Missing TLS certificates:** Ensure certificate paths are correct and accessible
- **Storage configuration:** Verify storage backend settings and permissions

---

### Wrong Command Arguments

**Error Messages:**
```bash
error: unexpected argument '--pub-url' found
error: unexpected argument '--priv-url' found
```

**Solution:** Update to current argument format:
```bash
# Old (deprecated):
--pub-url file:///path/to/keys
--priv-url file:///path/to/keys

# New (current):
--pub-path /path/to/keys
--priv-path /path/to/keys
```

---

## Docker & Container Issues

### Docker Build Failures

**Error Messages:**
```bash
pull access denied for tfhe-core, repository does not exist or may require 'docker login'
# or
Error loading from ghcr.io during docker image generation
```

**Solutions:**
```bash
# 1. Login to GitHub Container Registry
echo '<your-github-token>' | docker login ghcr.io -u <username> --password-stdin

# 2. For Chainguard images, login with proper token:
# Visit: https://console.chainguard.dev/org/zama.ai/settings/pull-tokens
# Use your Zama Google account (not GitHub)

# 3. Ensure token has proper permissions:
# - read:packages for GitHub
# - Zama organization access for Chainguard
```

---

### Container Size Limits

**Error Message:**
```bash
max 819200 bytes: exceeds limit: create wasm contract failed
```

**Root Cause:** Smart contract exceeds blockchain size limits.

**Solutions:**
```bash
# 1. Optimize WebAssembly build
# In dev.dockerfile, change from -Os to -Oz for aggressive optimization

# 2. Use cosmwasm optimizer
docker run --rm -v "$(pwd)":/code \
  --mount type=volume,source="$(basename "$(pwd)")_cache",target=/code/target \
  --mount type=volume,source=registry_cache,target=/usr/local/cargo/registry \
  cosmwasm/rust-optimizer:0.12.6

# 3. Consider splitting large contracts into smaller components
```

---

## 🔑 Key Management Issues

### Key Pair Mismatch

**Error Messages:**
```bash
Error in public decryption
Could not reconstruct decryption result
```

**Root Cause:** Public key doesn't match the deployed private key.

**Solution:**
```bash
# 1. Verify key pair consistency
kms-health-check live --endpoint localhost:50100

# 2. Copy correct public key from deployment source
# From S3:
aws s3 cp s3://your-bucket/keys/public.key ./keys/
# From container:
docker cp kms-container:/app/keys/public.key ./keys/
# From Kubernetes:
kubectl cp kms-pod:/app/keys/public.key ./keys/
```

**Prevention:**
- Always use key pairs generated together
- Implement key pair validation in deployment scripts
- Use consistent key naming conventions

---

### Insufficient Wallet Funds (Blockchain Integration)

**Error Message:**
```bash
account wasm1... not found
# or transaction failures
```

**Solutions:**
```bash
# 1. Check wallet balance
wasmd query bank balances <wallet-address>

# 2. Fund wallet from faucet or validator
# Faucet method:
curl -X POST "http://faucet-url/fund" -d '{"address":"<wallet-address>"}'

# Transfer from validator:
wasmd tx bank send <validator-address> <target-address> 1000000stake --fees 5000stake
```

---

## Performance Issues

### Too Many Open Files

**Error Message:**
```bash
Too many open files
```

**Solutions:**
```bash
# Temporary fix:
ulimit -n 4096

# Permanent fix (add to ~/.bash_profile or ~/.bashrc):
echo "ulimit -n 4096" >> ~/.bash_profile

# System-wide fix (/etc/security/limits.conf):
* soft nofile 4096
* hard nofile 8192
```

---

### High Memory Usage

**Symptoms:**
- Slow response times
- Pod restarts due to memory pressure
- OOMKilled events

**Solutions:**
```bash
# 1. Monitor memory usage (Kubernetes production)
kubectl top pods -n kms-threshold
kubectl describe pod kms-core-${PARTY_ID} -n kms-threshold | grep -A 10 "Limits\|Requests"

# 2. Increase memory limits
helm upgrade kms-party-${PARTY_ID} . \
  --set kmsCore.resources.limits.memory=48Gi \
  --set kmsCore.resources.requests.memory=32Gi \
  --wait

# 3. For Docker development environments
docker stats
htop

# 4. Scale horizontally (not applicable for single-party deployment)
# 5. Upgrade to higher memory instances (c7a.24xlarge)
```

---

## Diagnostic Commands

### Quick Health Check

> **Standard Commands**: See [Monitoring Guide](../monitoring-basics.md#standard-health-check-commands) for complete health check procedures.

```bash
# Emergency diagnostics only
kubectl get pods,events -n kms-threshold --sort-by='.lastTimestamp'
kubectl describe pod kms-core-${PARTY_ID} -n kms-threshold
```

### Service Status
```bash
# Kubernetes production
kubectl get pods,svc,pvc -n kms-threshold
kubectl logs -n kms-threshold kms-core-${PARTY_ID} --tail 50
kubectl top pods -n kms-threshold

# Docker development environments
docker ps
docker logs kms-container-name
docker stats
```

### Network Diagnostics
```bash
# Port connectivity
telnet localhost 50100
nc -zv localhost 50100

# DNS resolution
# DNS resolution for other parties
nslookup party1-external.kms-threshold.svc.cluster.local
dig party1-external.kms-threshold.svc.cluster.local

# Network latency to other parties
kubectl exec -n kms-threshold kms-core-${PARTY_ID} -- \
  ping party1-external.kms-threshold.svc.cluster.local
```

---

## Emergency Checklist

When encountering issues:

1. **Identify the Error**
   - [ ] Check error message against this guide
   - [ ] Note exact error text and context

2. **Quick Diagnostics**
   - [ ] Follow [Quick Reference](../quick-reference.md#emergency-health-check) emergency procedures
   - [ ] Check service status: `kubectl get pods -n kms-threshold`
   - [ ] Review recent events: `kubectl get events -n kms-threshold --sort-by='.lastTimestamp'`

3. **Apply Solution**
   - [ ] Follow specific solution from this guide
   - [ ] Test fix with health check tool
   - [ ] Monitor for recurrence

4. **Document & Prevent**
   - [ ] Document the incident and solution
   - [ ] Update monitoring/alerting if needed
   - [ ] Consider automation for common fixes

5. **Escalation**
   - [ ] If issue persists, gather logs and system information
   - [ ] Contact MPC development team with detailed information
   - [ ] Include configuration (sanitized) and error logs

---

## Related Documentation

- [Troubleshooting Guide](troubleshooting.md) - Systematic problem diagnosis
- [Metrics & Monitoring](metrics.md) - Monitoring tools and procedures
- [Deployment Guide](deployment.md) - Alternative deployment procedures
- [Configuration Management](../configuration.md) - Configuration best practices
