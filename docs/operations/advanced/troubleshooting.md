# KMS Advanced Troubleshooting Guide

**Systematic troubleshooting procedures for complex KMS operational issues in 13-party threshold deployments.**

> **Quick Fixes**: For immediate solutions to common problems, see [Common Errors](common-errors.md) and [Quick Reference](../quick-reference.md).

## Systematic Troubleshooting Approach

### 1. Information Gathering

Before starting troubleshooting, collect the following information:

```bash
# Kubernetes cluster information
kubectl version --short
kubectl get nodes
kubectl get pods,svc,pvc -n kms-threshold

# Your party's resource utilization
kubectl top pods -n kms-threshold
kubectl top nodes

# Network status (production ports)
kubectl exec -n kms-threshold kms-core-${PARTY_ID} -- \
  netstat -tlnp | grep -E "(50100|50001|9646)"

# For Docker development environments only
docker --version && docker ps -a | grep kms
```

### 2. Initial Health Assessment

> **Standard Health Checks**: See [Monitoring Guide](../monitoring-basics.md#standard-health-check-commands) for complete health check procedures.

```bash
# Kubernetes production health assessment
kubectl exec -n kms-threshold kms-core-${PARTY_ID} -- \
  kms-health-check live --endpoint localhost:50100

# Configuration validation (if needed)
kubectl exec -n kms-threshold kms-core-${PARTY_ID} -- \
  kms-health-check config --file /app/config/config.toml
```

### 3. Log Analysis

```bash
# Kubernetes production log analysis
kubectl logs -n kms-threshold kms-core-${PARTY_ID} --tail 100
kubectl logs -n kms-threshold kms-core-${PARTY_ID} -f

# Search for specific patterns
kubectl logs -n kms-threshold kms-core-${PARTY_ID} --tail 1000 | \
  grep -E "(ERROR|FATAL|PANIC|WARN)"

# Check recent events
kubectl get events -n kms-threshold --sort-by='.lastTimestamp' | tail -20

# For Docker development environments only
docker logs kms-container-name --tail 100 | grep -E "(ERROR|FATAL|PANIC|WARN)"
```

## Issue Classification & Resolution

### Service Startup Issues

**Symptoms:**
- Pod in CrashLoopBackOff state
- StatefulSet not ready
- Port binding errors

> **Quick Solutions**: See [Common Errors](common-errors.md) for immediate fixes to startup issues.

**Diagnostic Steps:**

1. **Check Pod Status**
   ```bash
   kubectl get pods -n kms-threshold -l app=kms-core
   kubectl describe pod kms-core-${PARTY_ID} -n kms-threshold
   kubectl logs -n kms-threshold kms-core-${PARTY_ID} --previous
   ```

2. **Verify Configuration**
   ```bash
   # Check ConfigMap
   kubectl get configmap -n kms-threshold -o yaml
   
   # Validate Helm values
   helm get values kms-party-${PARTY_ID} -n kms-threshold
   
   # Check PVC status
   kubectl get pvc -n kms-threshold
   ```

3. **Resource Constraints**
   ```bash
   # Check resource limits
   kubectl describe pod kms-core-${PARTY_ID} -n kms-threshold | grep -A 10 "Limits\|Requests"
   
   # Node resource availability
   kubectl top nodes
   kubectl describe node | grep -A 5 "Allocated resources"
   ```

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
   ```bash
   # Test basic connectivity
   telnet localhost 50100
   nc -zv localhost 50100
   
   # Test from different locations
   curl -f http://localhost:50100/health
   curl -f http://external-ip:50100/health
   ```

2. **Firewall & Security Groups**
   ```bash
   # Check local firewall
   iptables -L | grep 50100
   ufw status
   
   # Test from external hosts
   nmap -p 50100 your-kms-host
   ```

3. **DNS Resolution**
   ```bash
   # Verify hostname resolution
   nslookup kms-server
   dig kms-server
   
   # Test with IP address
   kms-health-check live --endpoint 192.168.1.100:50100
   ```

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
   ```bash
   # Real-time resource usage
   htop
   docker stats
   
   # Memory analysis
   free -h
   cat /proc/meminfo
   
   # Disk I/O
   iostat -x 1
   iotop
   ```

2. **Application Performance**
   ```bash
   # Request timing
   time kms-health-check live --endpoint localhost:50100
   
   # Concurrent load testing
   for i in {1..10}; do
     (time grpcurl -plaintext localhost:50100 kms.v1.CoreService/GetHealthStatus) &
   done
   wait
   ```

3. **Network Latency**
   ```bash
   # Ping test to peers
   for peer in kms-threshold-{1..4}; do
     ping -c 5 $peer
   done
   
   # Traceroute analysis
   traceroute kms-threshold-1
   ```

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
   ```bash
   # Check your party's connectivity to others
   kubectl exec -n kms-threshold kms-core-${PARTY_ID} -- \
     kms-health-check live --endpoint localhost:50100
   
   # Test connectivity to other parties (after network setup)
   kubectl exec -n kms-threshold kms-core-${PARTY_ID} -- \
     nc -zv party1-external.kms-threshold.svc.cluster.local 50001
   ```

2. **PRSS Setup Verification**
   ```bash
   # Check PRSS initialization status
   kubectl logs -n kms-threshold job/kms-party-${PARTY_ID}-threshold-init
   
   # Verify PRSS files in S3
   kubectl exec -n kms-threshold kms-core-${PARTY_ID} -- \
     aws s3 ls s3://zama-kms-party${PARTY_ID}-private/PRIV-p${PARTY_ID}/PrssSetup/
   ```

3. **Network Coordination**
   ```bash
   # Check PrivateLink VPC endpoints
   kubectl get svc -n kms-threshold | grep external
   
   # Verify DNS resolution to other parties
   kubectl exec -n kms-threshold kms-core-${PARTY_ID} -- \
     nslookup party1-external.kms-threshold.svc.cluster.local
   ```

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
   ```bash
   # Check file permissions
   ls -la keys/
   find keys/ -type f -exec ls -la {} \;
   
   # Verify directory structure
   tree keys/
   
   # Check disk space
   df -h /path/to/keys
   ```

2. **S3 Storage**
   ```bash
   # Test S3 connectivity
   aws s3 ls s3://your-kms-bucket/
   
   # Check credentials
   aws sts get-caller-identity
   
   # Test permissions
   aws s3 cp test-file s3://your-kms-bucket/test/
   aws s3 rm s3://your-kms-bucket/test/test-file
   ```

3. **Database Storage**
   ```bash
   # Test database connectivity
   psql -h db-host -U username -d kms_db -c "SELECT 1;"
   
   # Check table structure
   psql -h db-host -U username -d kms_db -c "\dt"
   ```

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
   kms-health-check live --endpoint localhost:50100 | grep -A 10 "KEY MATERIAL"
   
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
   grpcurl -plaintext localhost:50100 kms.v1.CoreService/GetOperatorPublicKey
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

ENDPOINT="localhost:50100"
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
kms-health-check live --endpoint localhost:50100 > "$DIAG_DIR/health-check.txt" 2>&1
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
- [Deployment Guide](deployment.md) - Alternative deployment procedures
- [Configuration Management](../configuration.md) - Configuration best practices
