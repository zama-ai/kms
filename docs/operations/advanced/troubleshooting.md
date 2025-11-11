# KMS Advanced Troubleshooting Guide

**Systematic troubleshooting procedures for complex KMS operational issues in 13-party threshold deployments.**

> **Quick Fixes**: For immediate solutions to common problems, see [Common Errors](common-errors.md) and [Emergency Procedures](../emergency-procedures.md).

## Systematic Troubleshooting Approach

### 1. Information Gathering

Before starting troubleshooting, collect the following information:

**System Information**:
- Kubernetes cluster version and node status
- Pod, service, and storage status
- Resource utilization (CPU, memory, storage)
- Network connectivity and port status

### 2. Initial Health Assessment

> **Standard Health Checks**: See [Monitoring Guide](../monitoring.md#standard-health-check-commands) for complete health check procedures.

**Health Assessment**:
- Use `kms-health-check` tool for comprehensive health verification
- Validate configuration syntax and settings
- Check service connectivity and responsiveness

### 3. Log Analysis

**Log Review**:
- Review recent logs for error patterns (ERROR, FATAL, PANIC, WARN)
- Check Kubernetes events for system-level issues
- Monitor logs in real-time during issue reproduction
- Focus on timestamps around when issues started

## Issue Classification & Resolution

### Service Startup Issues

**Symptoms:**
- Pod in CrashLoopBackOff state
- StatefulSet not ready
- Port binding errors

> **Quick Solutions**: See [Common Errors](common-errors.md) for immediate fixes to startup issues.

**Diagnostic Steps:**

1. **Check Pod Status**
   - Verify pod state and restart count
   - Review pod description for events and conditions
   - Check previous container logs if pod is restarting

2. **Verify Configuration**
   - Validate ConfigMap and Helm values
   - Check persistent volume claims status
   - Verify service account and RBAC permissions

3. **Resource Constraints**
   - Check resource limits and requests
   - Verify node resource availability and capacity

**Resolution Steps:**
1. Fix configuration errors in Helm values
2. Increase resource limits if needed
3. Verify PVC and storage class availability
4. Check node capacity and scheduling constraints

---

### Connectivity Issues

**Symptoms:**
- Connection refused errors
- Timeout errors
- Intermittent connectivity

**Diagnostic Steps:**

1. **Network Connectivity**
   - Test basic port connectivity with telnet or nc
   - Verify health endpoints are accessible
   - Test from different network locations

2. **Firewall & Security Groups**
   - Check local firewall rules and port access
   - Verify security group configurations
   - Test external connectivity with network tools

3. **DNS Resolution**
   - Verify hostname resolution for services
   - Check DNS configuration and records
   - Test with IP addresses to isolate DNS issues

**Resolution Steps:**
1. Verify service is running and listening on correct interface
2. Check firewall rules and security groups
3. Test with IP addresses to rule out DNS issues
4. Verify load balancer configuration if applicable

---

### Performance Issues

**Symptoms:**
- Slow response times
- High CPU/memory usage
- Request timeouts

**Diagnostic Steps:**

1. **Resource Monitoring**
   - Monitor real-time resource usage (CPU, memory, disk I/O)
   - Use system monitoring tools for detailed analysis
   - Check for resource bottlenecks and constraints

2. **Application Performance**
   - Measure request timing and response latency
   - Test concurrent load handling
   - Profile application performance patterns

3. **Network Latency**
   - Test connectivity and latency to other parties
   - Analyze network paths and routing
   - Identify network bottlenecks

**Optimization Steps:**
1. Scale resources (CPU, memory) if needed
2. Optimize network connectivity between peers
3. Review and tune configuration parameters
4. Consider horizontal scaling

---

### 13-Party Threshold Network Issues

**Symptoms:**
- Peer connectivity failures (< 5 parties reachable)
- Session synchronization issues
- PRSS setup problems

> **Network Requirements**: Your party needs connectivity to at least 4 other parties for t=4 threshold operations.

**Diagnostic Steps:**

1. **Your Party's Health Assessment**
   - Check your party's connectivity to others using `kms-health-check`
   - Test connectivity to other parties' external endpoints
   - Verify your party's health status and peer reachability

2. **PRSS Setup Verification**
   - Check PRSS initialization status in job logs
   - Verify PRSS setup using `kms-health-check` tool
   - Ensure PRSS files are present and accessible

3. **Network Coordination**
   - Check PrivateLink VPC endpoint configuration
   - Verify DNS resolution to other parties
   - Test connectivity to external services

**Resolution Steps:**
1. Coordinate with other parties to ensure their nodes are online
2. Verify PrivateLink VPC endpoint configuration with network coordinator
3. Check PRSS initialization completed across all 13 parties
4. Ensure your party's external service is accessible to others
5. Contact network coordinator for cross-party connectivity issues

---

### Storage Backend Issues

**Symptoms:**
- Key material not found
- Storage access errors
- Backup/restore failures

**Diagnostic Steps:**

1. **File Storage**
   - Check file permissions and ownership
   - Verify directory structure and key file presence
   - Check available disk space
   - Validate file integrity and accessibility

2. **Storage Connectivity**
   - Test storage connectivity using `kms-health-check` tool
   - Verify AWS credentials and permissions (if using S3)
   - Test read/write access to storage backend
   - Check network connectivity to storage services

3. **Database Storage**
   - Test database connectivity and authentication
   - Verify table structure and schema
   - Check database permissions and access rights

**Resolution Steps:**
1. Fix file permissions and ownership
2. Verify storage backend configuration
3. Test connectivity and credentials
4. Check available storage space
5. Validate backup and restore procedures

---

### Key Management Issues

**Symptoms:**
- Key generation failures
- Key validation errors
- Cryptographic operation failures

**Diagnostic Steps:**

1. **Key Inventory**
   ```bash
   # List available keys
   kms-health-check live --endpoint localhost:<GRPC_PORT> | grep -A 10 "KEY MATERIAL"
   
   # Check key files directly
   find keys/ -name "*.key" -o -name "*Key*" | head -10
   ```

2. **Key Validation**
   ```bash
   # Validate key format and integrity
   # (This depends on your key validation tools)
   
   # Check key permissions
   ls -la keys/*/
   ```

3. **Cryptographic Operations**
   ```bash
   # Test basic operations
   grpcurl -plaintext localhost:<GRPC_PORT> kms.v1.CoreService/GetOperatorPublicKey
   ```

**Resolution Steps:**
1. Regenerate corrupted or missing keys
2. Verify key format compatibility
3. Check cryptographic library versions
4. Validate key backup and recovery procedures

---

## Advanced Diagnostics

### Memory Analysis

```bash
# Memory usage breakdown
cat /proc/meminfo
ps aux --sort=-%mem | head -10

# Docker container memory
docker stats --no-stream --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}"

# Java heap dump (if applicable)
jmap -dump:live,format=b,file=heap.hprof <pid>
```

### Network Analysis

```bash
# Network connections
netstat -an | grep 50100
ss -tuln | grep 50100

# Traffic analysis
tcpdump -i any port 50100 -w kms-traffic.pcap

# Bandwidth testing
iperf3 -s  # On server
iperf3 -c server-ip  # On client
```

### Container Debugging

```bash
# Enter running container
docker exec -it kms-container-name /bin/bash

# Inspect container configuration
docker inspect kms-container-name

# Check container logs with timestamps
docker logs -t kms-container-name

# Monitor container events
docker events --filter container=kms-container-name
```

### Process Analysis

```bash
# Process tree
pstree -p $(pgrep kms)

# Open files
lsof -p $(pgrep kms)

# System calls
strace -p $(pgrep kms) -e trace=network

# Performance profiling
perf top -p $(pgrep kms)
```

## Emergency Procedures

### Service Recovery

1. **Graceful Restart**
   ```bash
   # Send SIGTERM for graceful shutdown
   docker-compose stop kms-server
   sleep 10
   docker-compose start kms-server
   ```

2. **Force Restart**
   ```bash
   # Force kill if graceful fails
   docker-compose kill kms-server
   docker-compose rm -f kms-server
   docker-compose up -d kms-server
   ```

3. **Full System Recovery**
   ```bash
   # Complete environment restart
   docker-compose down --volumes
   docker system prune -f
   docker-compose up -d
   ```

### Data Recovery

1. **Key Material Recovery**
   ```bash
   # Restore from backup
   cp -r /backup/keys/* /current/keys/
   chown -R kms:kms /current/keys/
   chmod -R 600 /current/keys/
   ```

2. **Configuration Recovery**
   ```bash
   # Restore known good configuration
   cp /backup/config.toml /current/config.toml
   kms-health-check config --file /current/config.toml
   ```

### Threshold Cluster Recovery

1. **Coordinated Restart**
   ```bash
   # Stop all peers simultaneously
   for peer in kms-threshold-{1..4}; do
     ssh $peer "docker-compose stop kms-server" &
   done
   wait
   
   # Start all peers simultaneously
   for peer in kms-threshold-{1..4}; do
     ssh $peer "docker-compose start kms-server" &
   done
   wait
   ```

2. **PRSS Re-initialization**
   ```bash
   # Only if PRSS is corrupted
   kms-init --addresses \
     http://kms-threshold-1:50100 \
     http://kms-threshold-2:50100 \
     http://kms-threshold-3:50100 \
     http://kms-threshold-4:50100
   ```

## Monitoring Integration

### Custom Health Checks

```bash
#!/bin/bash
# custom-health-check.sh

ENDPOINT="localhost:<GRPC_PORT>"
LOG_FILE="/var/log/kms-health.log"

# Function to log with timestamp
log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
}

# Comprehensive health check
check_health() {
    local status=0
    
    # Basic connectivity
    if ! kms-health-check live --endpoint "$ENDPOINT" >/dev/null 2>&1; then
        log_message "ERROR: Health check failed"
        status=1
    fi
    
    # Resource checks
    local mem_usage=$(free | grep Mem | awk '{printf "%.0f", $3/$2 * 100.0}')
    if [ "$mem_usage" -gt 90 ]; then
        log_message "WARNING: High memory usage: ${mem_usage}%"
        status=1
    fi
    
    local disk_usage=$(df / | tail -1 | awk '{print $5}' | sed 's/%//')
    if [ "$disk_usage" -gt 85 ]; then
        log_message "WARNING: High disk usage: ${disk_usage}%"
        status=1
    fi
    
    return $status
}

# Run check
if check_health; then
    log_message "INFO: All health checks passed"
    exit 0
else
    log_message "ERROR: Health check failures detected"
    exit 1
fi
```

### Automated Diagnostics

```bash
#!/bin/bash
# auto-diagnose.sh - Automated diagnostic collection

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
DIAG_DIR="/tmp/kms-diagnostics-$TIMESTAMP"
mkdir -p "$DIAG_DIR"

echo "Collecting KMS diagnostics to $DIAG_DIR..."

# System information
uname -a > "$DIAG_DIR/system-info.txt"
free -h > "$DIAG_DIR/memory-info.txt"
df -h > "$DIAG_DIR/disk-info.txt"
docker --version > "$DIAG_DIR/docker-version.txt"

# Service status
docker ps -a > "$DIAG_DIR/docker-containers.txt"
systemctl status kms > "$DIAG_DIR/service-status.txt" 2>&1

# Health checks
kms-health-check live --endpoint localhost:<GRPC_PORT> > "$DIAG_DIR/health-check.txt" 2>&1
kms-health-check config --file config.toml > "$DIAG_DIR/config-validation.txt" 2>&1

# Logs
docker logs kms-container-name --tail 1000 > "$DIAG_DIR/application-logs.txt" 2>&1
journalctl -u kms --since "1 hour ago" > "$DIAG_DIR/system-logs.txt" 2>&1

# Network information
netstat -tlnp > "$DIAG_DIR/network-ports.txt"
ss -tuln > "$DIAG_DIR/network-sockets.txt"

# Configuration (sanitized)
cp config.toml "$DIAG_DIR/config.toml.backup"
# Remove sensitive information
sed -E 's/(password|secret|key).*=.*/\1 = "[REDACTED]"/' config.toml > "$DIAG_DIR/config-sanitized.toml"

# Create archive
tar -czf "kms-diagnostics-$TIMESTAMP.tar.gz" -C /tmp "kms-diagnostics-$TIMESTAMP"
echo "Diagnostics collected: kms-diagnostics-$TIMESTAMP.tar.gz"
```

## Troubleshooting Checklist

### Initial Assessment
- [ ] Identify and document the specific error or symptom
- [ ] Note when the issue started and any recent changes
- [ ] Check if the issue affects all users or specific operations
- [ ] Gather system information and current status

### Basic Diagnostics
- [ ] Run health check tool for automated diagnostics
- [ ] Check service status and recent logs
- [ ] Verify resource utilization (CPU, memory, disk)
- [ ] Test basic connectivity and network access

### Configuration Review
- [ ] Validate configuration files for syntax errors
- [ ] Check file permissions and ownership
- [ ] Verify storage backend accessibility
- [ ] Review recent configuration changes

### Advanced Investigation
- [ ] Analyze detailed logs for error patterns
- [ ] Test individual components in isolation
- [ ] Check dependencies and external services
- [ ] Review security and firewall settings

### Resolution & Validation
- [ ] Apply appropriate fix based on root cause
- [ ] Test the fix thoroughly
- [ ] Monitor for recurrence
- [ ] Document the issue and solution

### Prevention
- [ ] Update monitoring and alerting if needed
- [ ] Consider automation for similar issues
- [ ] Review and update documentation
- [ ] Share learnings with the team

---

## Related Documentation

- [Common Errors](common-errors.md) - Quick fixes for frequent issues
- [Metrics & Monitoring](metrics.md) - Monitoring tools and procedures
- [Kubernetes Deployment](kubernetes-deployment.md) - Alternative deployment procedures
- [Configuration Management](../configuration.md) - Configuration best practices
