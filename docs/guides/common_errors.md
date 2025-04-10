# Common Deployment Errors

## Deployment Errors

### Out of Memory error

**Error message**: Out of Memory error, OOMKilled

**Cause**: The server doesn't have enough memory.

**Possible solutions**: Use a more beefy server. Currently, we use `hpc7a` machines for our benchmarks, with 192 cores and 768 G of RAM.

---

### No space left on device

**Error message**: No space left on device

**Cause**: The server doesn't have enough disk.

**Possible solutions**: Increase the disk capacity of your instance. In addition, think of using a more beefy server in term of vCPU and memory. Currently, we use `hpc7a` machines for our benchmarks, with 192 cores and 768 G of memory. Also, you can choose `c7i.metal-24xl` with 96 cores and 192 G of memory.

---

### Error related to PRSS setup

**Error message**:

```bash
No PRSS setup exists
```

**Cause**: The threshold servers have not executed the init step to ensure that preprocessed material is there. This should be done automatically by the CI during the launching process, but can also be done manually from the CI core/service/src/bin/kms-init.rs. However, be aware that this must be done for all parties at the same time.

**Possible solutions**: Run a command like this:

```bash
kms-init --addresses http://kms-threshold-1-threshold-core_kms-threshold_svc_50100.mesh:80 http://kms-threshold-2-threshold-core_kms-threshold_svc_50100.mesh:80 http://kms-threshold-3-threshold-core_kms-threshold_svc_50100.mesh:80 http://kms-threshold-4-threshold-core_kms-threshold_svc_50100.mesh:80
```

You can also faced this error message regarding PRSS:

```bash
WARN kms_lib::threshold::threshold_kms: failed to read PRSS from file with error: No such file or directory (os error 2)
INFO kms_lib::threshold::threshold_kms: Initializing threshold KMS server without PRSS Setup, remember to call the init GRPC endpoint
```

**Cause**: The PRSS Setup file should be stored under keys/PRIV-pX/PrssSetup/000..0001 in PRIV-pX  (where pX refers to the parties p1, p2, etc.) and is not located there or is corrupted.

**Possible solutions**: Check the PRSS Setup file location and make sure it is correct.


## Development Errors

### Too many files error

**Error message**:

```bash
Too many open files
```

**Cause**: Not enough file descriptors.

**Possible solutions**: Increase the number of file descriptors.
Adding the ulimit -n 1024 statement to your bash profile using sudo nano .bash_profile handles it.

---

### Result of decryption is incorrect

**Error message**: Happened once because the public key being used was not the proper pair of the private key being deployed.

**Cause**: Do not rely on the name of the key to make sure that you have a proper pair.

**Possible solutions**: In this case copy the public key from the adequate place (S3 bucket, Docker container, Kubernetes pod …)