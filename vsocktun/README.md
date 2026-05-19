# vsocktun

`vsocktun` is a small utility that relays packets between a Linux TUN device
and one or more VSOCK streams.

It is designed for the Nitro Enclave deployment in this repository, where the
enclave gets an IP address on a private point-to-point subnet and all of its
traffic is forwarded through the parent instance over VSOCK. The parent now
also serves the enclave's tunnel CIDR, shard count, MTU, and rewritten
resolver config over an initial bootstrap exchange on that same VSOCK port.

## Architecture

`vsocktun` is a packet tunnel, not a TCP proxy.

That means:
- the inner gRPC peer connections stay end-to-end TCP connections
- `vsocktun` does not terminate or re-originate inner TCP flows
- packet boundaries are preserved explicitly by a small framing layer on top of
  the stream-oriented VSOCK transport
- when both ends support Linux virtio-net headers, `vsocktun` forwards raw TUN
  frames end-to-end so GSO and checksum metadata survive across VSOCK

The tunnel is organized around two levels:

- A **session** is one logical tunnel between enclave and parent.
- A **shard** is one TUN queue paired with one VSOCK stream.

Each shard carries a subset of the tunnel traffic. Using multiple shards avoids
forcing every inner flow through one ordered outer stream, which reduces head
of-line blocking under concurrent MPC traffic.

The TUN device is configured with Linux offload support through `tun-rs`. When
that succeeds on both sides, the tunnel carries raw TUN frames, including the
virtio-net metadata needed for TCP segmentation and checksum offload. If both
sides fall back to plain L3 TUN packets, the relay still works, but without the
same offload preservation.

## Responsibilities

`vsocktun` owns:
- creating the local multiqueue TUN device
- serving bootstrap tunnel configuration from the parent to the enclave
- connecting or accepting the VSOCK shard streams
- grouping the shard streams into one logical session
- forwarding packets between TUN queues and VSOCK streams
- installing enclave-side routes through the parent tunnel IP
- writing the enclave `/etc/resolv.conf` received from the parent bootstrap
- reconnecting from the enclave side when a session breaks

`vsocktun` does **not** own:
- IP address allocation policy
- NAT / masquerading
- ingress DNAT
- DNS forwarding

Those pieces are intentionally left to the surrounding shell scripts and Helm
templates used by the KMS deployment.

## Modes

`vsocktun` has two modes.

### Parent mode

The parent side creates the TUN device once, serves bootstrap requests on the
shared VSOCK port, and then listens for shard streams from the enclave. The
parent derives the enclave-side CIDR from `--tun-address` and
`--enclave-address` before returning it in bootstrap.

```bash
vsocktun parent \
  --tun-name vsocktun \
  --tun-address 10.118.0.1/24 \
  --enclave-address 10.118.0.2 \
  --vsock-port 2100 \
  --queues 32 \
  --tokio-worker-threads 8
```

### Enclave mode

The enclave side first bootstraps its TUN address, queue count, MTU, routes,
and resolver config from the parent, then creates its TUN device once and
repeatedly dials the parent until a full session is established.

```bash
vsocktun enclave \
  --parent-cid 3 \
  --tun-name vsocktun \
  --vsock-port 2100 \
  --tokio-worker-threads 8
```

## Key flags

- `--tun-name`: local TUN interface name
- `--vsock-port`: parent-side VSOCK port used first for bootstrap and then for
  shard sessions
- `--tokio-worker-threads`: number of Tokio runtime worker threads used to
  drive all shard tasks in the process
- `-v, --verbose`: raise log level from `info` to `debug`
- `-vv`: raise log level to `trace` and include per-packet forwarding summaries

Parent-only:
- `--tun-address`: parent-side IPv4 address and prefix for the tunnel interface
- `--enclave-address`: enclave-side IPv4 address without the CIDR prefix
- `--queues`: number of shards / TUN queues / VSOCK streams in the session
- `--mtu`: optional TUN MTU override propagated to the enclave bootstrap
- `--session-timeout-secs`: how long the parent waits for all shards of a new
  session to arrive and complete their initial session headers

Enclave-only:
- `--parent-cid`: VSOCK CID of the parent instance, normally `3` on Nitro
- `--reconnect-delay-ms`: delay before retrying a failed session

## Operational notes

- Both sides must use the same `--vsock-port`.
- The parent is the source of truth for enclave tunnel addressing, shard count,
  MTU, and resolver contents.
- Both sides must run compatible `vsocktun` protocol versions. Newer binaries
  reject older handshake versions during session setup.
- If peer TUN offload framing support differs between parent and enclave,
  session setup is rejected with an explicit log message instead of silently
  downgrading.
- The parent and enclave TUN addresses must be on the same point-to-point
  subnet.
- The parent-side runtime still needs IP forwarding and NAT configured outside
  `vsocktun`.
- The parent-side runtime still needs `dnsproxy` (or equivalent) configured
  outside `vsocktun`.

## Debugging

When traffic does not appear to flow through the tunnel:

- default output uses `info` for lifecycle and `error` for failures
- use `-v` to enable `debug` logs for session assembly, shard startup, and cancellation decisions
- use `-vv` to enable `trace` logs for packet direction and byte counts per shard
- packet logs intentionally omit payload contents and only report metadata

In this repository, those surrounding concerns are handled by:
- `docker/core/service/start_parent_proxies.sh`
- `docker/core/service/init_enclave.sh`
- `charts/kms-core/templates/_helpers.tpl`

## Example deployment shape

The current KMS deployment uses `vsocktun` like this:

- parent side:
  - bring up `vsocktun`
  - enable IP forwarding
  - add NAT / FORWARD rules
  - DNAT ingress ports into the enclave IP
  - run `dnsproxy`

- enclave side:
  - bring up `vsocktun`
  - fetch tunnel config and rewritten `resolv.conf` from the parent
  - let `vsocktun` install the local routes and resolver settings

This keeps `vsocktun` focused on one job: carrying packet traffic efficiently
between the enclave and its parent over VSOCK.
