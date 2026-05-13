use anyhow::{Context, Result, bail};
use std::net::Ipv4Addr;
use tun_rs::{DeviceBuilder, Layer, SyncDevice, VIRTIO_NET_HDR_LEN};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Ipv4Cidr {
    address: Ipv4Addr,
    prefix_len: u8,
}

impl Ipv4Cidr {
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

    pub(crate) fn address(&self) -> Ipv4Addr {
        self.address
    }

    pub(crate) fn prefix_len(&self) -> u8 {
        self.prefix_len
    }
}

pub(crate) struct TunDevice {
    queues: Vec<SyncDevice>,
}

impl TunDevice {
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

        let mut queues = Vec::with_capacity(queue_count);
        queues.push(first);
        for _ in 1..queue_count {
            let cloned = queues[0]
                .try_clone()
                .with_context(|| format!("failed to clone tun-rs queue for '{name}'"))?;
            queues.push(cloned);
        }

        Ok(Self { queues })
    }

    pub(crate) fn queue_count(&self) -> usize {
        self.queues.len()
    }

    pub(crate) fn clone_queues(&self) -> Result<Vec<SyncDevice>> {
        self.queues
            .iter()
            .map(|queue| {
                queue
                    .try_clone()
                    .context("failed to duplicate tun-rs queue handle")
            })
            .collect()
    }

    pub(crate) fn max_frame_bytes(&self) -> usize {
        VIRTIO_NET_HDR_LEN + 65535
    }
}

#[cfg(test)]
mod tests {
    use super::Ipv4Cidr;
    use std::net::Ipv4Addr;

    #[test]
    fn parses_cidr_and_prefix() {
        let cidr = Ipv4Cidr::parse("10.118.0.2/24").expect("CIDR should parse");
        assert_eq!(cidr.address(), Ipv4Addr::new(10, 118, 0, 2));
        assert_eq!(cidr.prefix_len(), 24);
    }

    #[test]
    fn rejects_invalid_prefix() {
        let err =
            Ipv4Cidr::parse("10.118.0.2/33").expect_err("CIDR should reject prefixes over 32");
        assert!(err.to_string().contains("at most 32"));
    }
}
