# distributed-decryption
[![Rust](https://github.com/zama-ai/distributed-decryption/actions/workflows/rust.yml/badge.svg)](https://github.com/zama-ai/distributed-decryption/actions/workflows/rust.yml)


To run a 10 party benchmark for distributed decryption on a local network run the following:

```sh
docker build -t ddec .
cd experiments/10
docker compose up
```

By default the docker images run a distributed decryption with session id equal
to 1. To collect statistics about timings on different parties run the
following:

```sh
docker exec -it 10-choreo-1 bash
RUST_LOG=info mobygo -n 4 results --session-id 1
```

To simulate a certain network connection on all containers run the following (replace `wan.sh` with the desired network below):
```sh
# configure network on all running containers
./docker/runinallcontainers.sh wan.sh
# verify that ping latency has changed as desired
docker exec distributed-decryption-p1-1 ping distributed-decryption-p2-1
```

The following networks are simulated using `tc`:

| Network Config  | Script | Latency | Bandwidth |
| --- | --- | --- | --- |
| None  | `off.sh`  | none  | no limit  |
| WAN  | `wan.sh`  | 50 ms  | 100 Mbit/s  |
| 1 Gbps LAN  | `lan1.sh`  | 0.5 ms  | 1 Gbit/s  |
| 10 Gbps LAN  | `lan10.sh`  | 0.5 ms  | 10 Gbit/s  |

Note that ping RTT will be 2x the latency from the table, when the network config is set on all nodes.
