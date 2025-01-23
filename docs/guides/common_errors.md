# Common Errors

## Out of Memory error

**Error message**: Out of Memory error, OOMKilled

**Cause**: The server doesn't have enough memory.

**Possible solutions**: Use a more beefy server. Currently, we use `hpc7a` machines for our benchmarks, with 192 cores and 768 G of RAM.

## No space left on device

**Error message**: No space left on device

**Cause**: The server doesn't have enough disk.

**Possible solutions**: Increase the disk capacity of your instance. In addition, think of using a more beefy server in term of vCPU and memory. Currently, we use `hpc7a` machines for our benchmarks, with 192 cores and 768 G of memory. Also, you can choose `c7i.metal-24xl` with 96 cores and 192 G of memory.




