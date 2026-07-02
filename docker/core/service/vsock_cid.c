/*
 * vsock-cid: print this context's local vsock CID to stdout.
 *
 * Inside a Nitro enclave this returns the enclave CID assigned by the parent
 * (via enclave.json / nitro-cli run-enclave --enclave-cid). init_enclave.sh
 * uses it to derive per-enclave parent vsock ports so a single EIF can back
 * multiple co-located enclaves without vsock port collisions on the host.
 */
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/vm_sockets.h>

int main(void) {
    int fd = open("/dev/vsock", O_RDONLY);
    if (fd < 0) {
        perror("open /dev/vsock");
        return 1;
    }

    unsigned int cid = 0;
    if (ioctl(fd, IOCTL_VM_SOCKETS_GET_LOCAL_CID, &cid) < 0) {
        perror("ioctl IOCTL_VM_SOCKETS_GET_LOCAL_CID");
        close(fd);
        return 1;
    }

    close(fd);
    printf("%u\n", cid);
    return 0;
}
