# vsocktun

`vsocktun` is a small utility that relays packets between a Linux TUN device
and one or more VSOCK streams.

It is designed for the Nitro Enclave deployment in this repository, where the
enclave gets an IP address on a private point-to-point subnet and all of its
traffic is forwarded through the parent instance over VSOCK.

## Architecture

`vsocktun` is a packet tunnel, not a TCP proxy.

That means:
- the inner gRPC peer connections stay end-to-end TCP connections
- `vsocktun` does not terminate or re-originate inner TCP flows
- packet boundaries are preserved explicitly by a small framing layer on top of
  the stream-oriented VSOCK transport

The tunnel is organized around two levels:

- A **session** is one logical tunnel between enclave and parent.
- A **shard** is one TUN queue paired with one VSOCK stream.

Each shard carries a subset of the tunnel traffic. Using multiple shards avoids
forcing every inner flow through one ordered outer stream, which reduces head
of-line blocking under concurrent MPC traffic.

The TUN device is configured with Linux offload support through `tun-rs`, so
the tunnel can carry coalesced or segmented traffic instead of always forcing
one outer packet per inner TCP segment.

## Responsibilities

`vsocktun` owns:
- creating the local multiqueue TUN device
- connecting or accepting the VSOCK shard streams
- grouping the shard streams into one logical session
- forwarding packets between TUN queues and VSOCK streams
- reconnecting from the enclave side when a session breaks

`vsocktun` does **not** own:
- IP address allocation policy
- route management outside the local TUN interface
- NAT / masquerading
- ingress DNAT
- DNS forwarding
- copying `/etc/resolv.conf`

Those pieces are intentionally left to the surrounding shell scripts and Helm
templates used by the KMS deployment.

## Modes

`vsocktun` has two modes.

### Parent mode

The parent side creates the TUN device once and listens for shard streams from
the enclave.

```bash
vsocktun parent \
  --tun-name vsocktun \
  --tun-address 10.118.0.1/24 \
  --vsock-port 2100 \
  --queues 32
```

### Enclave mode

The enclave side creates its TUN device once and repeatedly dials the parent
until a full session is established.

```bash
vsocktun enclave \
  --parent-cid 3 \
  --tun-name vsocktun \
  --tun-address 10.118.0.2/24 \
  --vsock-port 2100 \
  --queues 32
```

## Key flags

- `--tun-name`: local TUN interface name
- `--tun-address`: local IPv4 address and prefix for the tunnel interface
- `--vsock-port`: parent-side VSOCK port used for the tunnel session
- `--queues`: number of shards / TUN queues / VSOCK streams in the session
- `--mtu`: optional TUN MTU override

Parent-only:
- `--session-timeout-secs`: how long the parent waits for all shards of a new
  session to arrive

Enclave-only:
- `--parent-cid`: VSOCK CID of the parent instance, normally `3` on Nitro
- `--reconnect-delay-ms`: delay before retrying a failed session

## Operational notes

- Both sides must agree on `--queues` and `--vsock-port`.
- The parent and enclave TUN addresses must be on the same point-to-point
  subnet.
- The parent-side runtime still needs IP forwarding and NAT configured outside
  `vsocktun`.
- The enclave-side runtime still needs routes and DNS wiring configured outside
  `vsocktun`.

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
  - receive config and resolver data from the parent
  - bring up `vsocktun`
  - add local routes through the parent tunnel IP
  - point resolver settings at the parent-side DNS bridge

This keeps `vsocktun` focused on one job: carrying packet traffic efficiently
between the enclave and its parent over VSOCK.
