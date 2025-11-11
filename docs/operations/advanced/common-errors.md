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
- Check memory usage with `kubectl top pods` or `docker stats`
- Increase memory limits to 32Gi in Helm values or Docker configuration
- Restart the service after resource adjustment

**Prevention:**
- Minimum 32Gi RAM for production (96Gi allocated to Nitro Enclaves)
- 8Gi RAM minimum for development/testing
- Monitor with `kubectl top pods` or Prometheus metrics

---

### No Space Left on Device

**Error Message:**
```bash
No space left on device
```

**Immediate Solution:**
- Check disk usage with `df -h` or `kubectl get pvc`
- Clean up unnecessary files or Docker volumes
- Increase PVC size for Kubernetes deployments
- Expand storage allocation in your environment

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
- Enable PRSS initialization in Helm values (`kmsInit.enabled=true`)
- Coordinate with network coordinator for multi-party initialization
- Monitor initialization logs and verify PRSS files are created
- Use `kms-health-check` tool to verify PRSS setup completion

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
- Check if KMS pod/container is running
- Test connectivity with `kms-health-check` tool
- Verify service status and endpoints
- Check recent logs for error details

**Common Solutions:**
- Restart the service if it's not running
- Verify network connectivity and port configuration
- Check resource limits and availability
- Review service configuration for errors

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
   - Check party synchronization with `kms-health-check` tool
   - Verify connectivity to other parties in the network
   - Ensure all parties are online and responsive
   - Check network latency and stability between parties

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
- Check TFHE versions in use across all components
- Regenerate keys with the current TFHE version
- Update coprocessor image to match TFHE version
- Ensure all components use compatible TFHE-rs versions

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
- Replace `--pub-url` with `--pub-path`
- Replace `--priv-url` with `--priv-path`
- Use local file paths instead of file:// URLs

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
- Login to GitHub Container Registry with proper token
- For Chainguard images, use Zama organization access tokens
- Ensure tokens have read:packages permissions
- Visit registry console to generate proper access tokens

---

### Container Size Limits

**Error Message:**
```bash
max 819200 bytes: exceeds limit: create wasm contract failed
```

**Root Cause:** Smart contract exceeds blockchain size limits.

**Solutions:**
- Optimize WebAssembly build with aggressive optimization flags
- Use cosmwasm optimizer for size reduction
- Consider splitting large contracts into smaller components
- Review contract code for unnecessary dependencies

---

### Docker Registry Authentication Issues

**Error Messages:**
```bash
Error loading from ghcr.io during docker image generation
# or
pull access denied for repository, may require 'docker login'
```

**Root Cause:** Authentication issues with container registries or missing access permissions.

**Solutions:**
- Login to GitHub Container Registry with proper authentication
- For Chainguard images, use Zama organization access tokens
- Verify token permissions for registry access
- Use service accounts for automated deployments

**Prevention:**
- Set up proper registry authentication in CI/CD pipelines
- Use service accounts for automated deployments
- Regularly rotate access tokens

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
- Verify key pair consistency with `kms-health-check` tool
- Copy correct public key from deployment source
- Ensure public and private keys were generated together
- Validate key pair before deployment

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
- Check wallet balance using blockchain query commands
- Fund wallet from faucet or validator
- Ensure sufficient funds for transaction fees
- Monitor wallet balance regularly

---

## Performance Issues

### Too Many Open Files

**Error Message:**
```bash
Too many open files
```

**Solutions:**
- Increase file descriptor limits with `ulimit -n 4096`
- Add ulimit settings to shell profile for permanent fix
- Configure system-wide limits in `/etc/security/limits.conf`
- Restart services after applying changes

---

### High Memory Usage

**Symptoms:**
- Slow response times
- Pod restarts due to memory pressure
- OOMKilled events

**Solutions:**
- Monitor memory usage with `kubectl top pods` or `docker stats`
- Increase memory limits in Helm values or Docker configuration
- Upgrade to higher memory instances if needed
- Review memory usage patterns and optimize if possible

---

## Diagnostic Commands

### Quick Health Check

> **Standard Commands**: See [Monitoring Guide](../monitoring.md#standard-health-check-commands) for complete health check procedures.

**Emergency Diagnostics**:
- Use `kms-health-check` tool for comprehensive health verification
- Check pod/container status and recent events
- Review logs for error details

### Service Status
**Status Verification**:
- Check pods, services, and storage status
- Review recent logs for errors
- Monitor resource usage
- See [Monitoring Guide](../monitoring.md) for detailed procedures

### Network Diagnostics
**Connectivity Testing**:
- Test port connectivity and DNS resolution
- Check network latency to other parties
- Verify service discovery and endpoints
- See [Troubleshooting Guide](troubleshooting.md) for detailed network diagnostics

---

## Related Documentation

- [Troubleshooting Guide](troubleshooting.md) - Systematic problem diagnosis
- [Metrics & Monitoring](metrics.md) - Monitoring tools and procedures
- [Kubernetes Deployment](kubernetes-deployment.md) - Alternative deployment procedures
- [Configuration Management](../configuration.md) - Configuration best practices
