//! TUN device ownership for `vsocktun`.
//!
//! This module is intentionally narrow: it turns the CLI-facing tunnel
//! configuration into a multiqueue `tun-rs` device and hands queue handles back
//! to the session runner. Route setup, NAT, and DNS stay outside this crate in
//! the surrounding shell scripts.

use anyhow::{Context, Result, bail};
use std::net::Ipv4Addr;
use std::sync::Mutex;
use tun_rs::{AsyncDevice, DeviceBuilder, Layer, VIRTIO_NET_HDR_LEN};

/// Parsed IPv4 interface address for one end of the point-to-point tunnel.
///
/// The CLI accepts `A.B.C.D/prefix`, but `tun-rs` wants the address and prefix
/// as separate values when configuring the interface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Ipv4Cidr {
    address: Ipv4Addr,
    prefix_len: u8,
}

impl Ipv4Cidr {
    /// Parses the CLI's `A.B.C.D/prefix` syntax into validated IPv4 parts.
    pub(crate) fn parse(value: &str) -> Result<Self> {
        let (address, prefix_len) = value
            .split_once('/')
            .context("CIDR address must contain a '/' separator")?;
        let address = address
            .parse::<Ipv4Addr>()
            .with_context(|| format!("invalid IPv4 address '{address}'"))?;
        let prefix_len = prefix_len
            .parse::<u8>()
            .with_context(|| format!("invalid IPv4 prefix '{prefix_len}'"))?;
        if prefix_len > 32 {
            bail!("IPv4 prefix length must be at most 32");
        }

        Ok(Self {
            address,
            prefix_len,
        })
    }

    /// Returns the host address assigned to the local TUN interface.
    pub(crate) fn address(&self) -> Ipv4Addr {
        self.address
    }

    /// Returns the network prefix length passed to the kernel TUN setup.
    pub(crate) fn prefix_len(&self) -> u8 {
        self.prefix_len
    }
}

/// The long-lived local TUN interface together with its queue handles.
///
/// `vsocktun` keeps the device for the lifetime of the process and clones new
/// queue handles for each accepted tunnel session.
pub(crate) struct TunDevice {
    queues: Mutex<Vec<AsyncDevice>>,
    uses_vnet_hdr: bool,
}

impl TunDevice {
    /// Creates the multiqueue TUN device that backs one side of the tunnel.
    ///
    /// The device itself lives for the process lifetime. Individual sessions
    /// later borrow the queue handles so `vsocktun` can reconnect without
    /// recreating the interface or disturbing routes owned by the shell scripts.
    pub(crate) fn create(
        name: &str,
        cidr: &Ipv4Cidr,
        queue_count: usize,
        mtu: Option<u32>,
    ) -> Result<Self> {
        if queue_count == 0 {
            bail!("queue count must be at least one");
        }

        let mtu = match mtu {
            Some(mtu) => u16::try_from(mtu).context("MTU must fit in u16 for tun-rs")?,
            None => 1500,
        };

        let mut builder = DeviceBuilder::new()
            .name(name)
            .layer(Layer::L3)
            .ipv4(cidr.address(), cidr.prefix_len(), None)
            .mtu(mtu)
            .offload(true)
            .packet_information(false);

        if queue_count > 1 {
            builder = builder.multi_queue(true);
        }

        let first = builder
            .build_sync()
            .with_context(|| format!("failed to build tun-rs device '{name}'"))?;

        let mut sync_queues = Vec::with_capacity(queue_count);
        sync_queues.push(first);
        for _ in 1..queue_count {
            let cloned = sync_queues[0]
                .try_clone()
                .with_context(|| format!("failed to clone tun-rs queue for '{name}'"))?;
            sync_queues.push(cloned);
        }

        let queues = sync_queues
            .into_iter()
            .enumerate()
            .map(|(queue, device)| {
                AsyncDevice::new(device)
                    .with_context(|| format!("failed to make TUN queue {queue} asynchronous"))
            })
            .collect::<Result<Vec<_>>>()?;

        let uses_vnet_hdr = queues
            .first()
            .expect("TunDevice::create should always build at least one queue")
            .tcp_gso();

        Ok(Self {
            queues: Mutex::new(queues),
            uses_vnet_hdr,
        })
    }

    /// Returns how many queue handles this device currently exposes.
    pub(crate) fn queue_count(&self) -> usize {
        self.queues
            .lock()
            .expect("TUN queue mutex should not be poisoned")
            .len()
    }

    /// Lends the full queue set to one logical session.
    ///
    /// Only one session may own the queues at a time because each shard worker
    /// performs blocking packet I/O directly on its assigned queue.
    pub(crate) fn take_queues(&self) -> Result<Vec<AsyncDevice>> {
        let mut queues = self
            .queues
            .lock()
            .expect("TUN queue mutex should not be poisoned");
        if queues.is_empty() {
            bail!("TUN queues are already in use by another session");
        }

        Ok(std::mem::take(&mut *queues))
    }

    /// Returns the queue set after one logical session finishes.
    ///
    /// Callers must give every queue back, even after errors, so the next
    /// session can reuse the same interface cleanly.
    pub(crate) fn restore_queues(&self, queues: Vec<AsyncDevice>) {
        let mut stored = self
            .queues
            .lock()
            .expect("TUN queue mutex should not be poisoned");
        *stored = queues;
    }

    /// Returns the largest packet buffer `vsocktun` should allocate for one
    /// read from this device.
    ///
    /// When offloads are enabled the kernel may prepend a virtio-net header, so
    /// the relay reserves room for that header plus the largest standard IP
    /// packet it will forward.
    pub(crate) fn max_frame_bytes(&self) -> usize {
        VIRTIO_NET_HDR_LEN + 65535
    }

    /// Reports whether this kernel/TUN combination uses virtio-net framing.
    ///
    /// Both tunnel endpoints advertise this in the VSOCK handshake so they
    /// agree on whether framed payloads carry raw TUN frames or plain L3 bytes.
    pub(crate) fn uses_vnet_hdr(&self) -> bool {
        self.uses_vnet_hdr
    }
}

#[cfg(test)]
mod tests {
    use super::Ipv4Cidr;
    use std::net::Ipv4Addr;

    #[test]
    fn parses_cidr_and_prefix() {
        // This proves the CLI parser preserves both address parts exactly before
        // they are handed to tun-rs for interface creation.
        let cidr = Ipv4Cidr::parse("10.118.0.2/24").expect("CIDR should parse");
        assert_eq!(cidr.address(), Ipv4Addr::new(10, 118, 0, 2));
        assert_eq!(cidr.prefix_len(), 24);
    }

    #[test]
    fn rejects_invalid_prefix() {
        // This guards the early validation path so a bad CLI prefix fails before
        // we attempt any privileged TUN setup.
        let err =
            Ipv4Cidr::parse("10.118.0.2/33").expect_err("CIDR should reject prefixes over 32");
        assert!(err.to_string().contains("at most 32"));
    }
}
