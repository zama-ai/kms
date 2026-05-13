use crate::sys;
use anyhow::{Context, Result, bail};
use std::fs::File;
use std::net::Ipv4Addr;
use std::process::Command;

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

    fn netmask(&self) -> Ipv4Addr {
        let raw = if self.prefix_len == 0 {
            0
        } else {
            u32::MAX << (32 - u32::from(self.prefix_len))
        };
        Ipv4Addr::from(raw)
    }
}

#[derive(Debug)]
pub(crate) struct TunDevice {
    queues: Vec<File>,
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

        let mut queues = Vec::with_capacity(queue_count);
        for _ in 0..queue_count {
            let file = File::options()
                .read(true)
                .write(true)
                .open("/dev/net/tun")
                .context("failed to open /dev/net/tun")?;

            let mut flags = sys::IFF_TUN | sys::IFF_NO_PI;
            if queue_count > 1 {
                flags |= sys::IFF_MULTI_QUEUE;
            }

            let mut request =
                sys::IfReq::new(name, flags).context("failed to prepare TUN request")?;
            sys::tun_set_iff(&file, &mut request)
                .with_context(|| format!("failed to attach queue to TUN interface '{name}'"))?;
            queues.push(file);
        }

        configure_interface(name, cidr, mtu)?;
        Ok(Self { queues })
    }

    pub(crate) fn queue_count(&self) -> usize {
        self.queues.len()
    }

    pub(crate) fn clone_queues(&self) -> Result<Vec<File>> {
        self.queues
            .iter()
            .map(|queue| {
                queue
                    .try_clone()
                    .context("failed to duplicate TUN queue handle")
            })
            .collect()
    }
}

fn configure_interface(name: &str, cidr: &Ipv4Cidr, mtu: Option<u32>) -> Result<()> {
    let status = Command::new("ifconfig")
        .arg(name)
        .arg(cidr.address().to_string())
        .arg("netmask")
        .arg(cidr.netmask().to_string())
        .arg("up")
        .status()
        .with_context(|| format!("failed to run ifconfig for interface '{name}'"))?;

    if !status.success() {
        bail!("ifconfig failed while configuring interface '{name}'");
    }

    if let Some(mtu) = mtu {
        let status = Command::new("ifconfig")
            .arg(name)
            .arg("mtu")
            .arg(mtu.to_string())
            .status()
            .with_context(|| format!("failed to set MTU on interface '{name}'"))?;

        if !status.success() {
            bail!("ifconfig failed while setting MTU on interface '{name}'");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::Ipv4Cidr;
    use std::net::Ipv4Addr;

    #[test]
    fn parses_cidr_and_netmask() {
        let cidr = Ipv4Cidr::parse("10.118.0.2/24").expect("CIDR should parse");
        assert_eq!(cidr.address(), Ipv4Addr::new(10, 118, 0, 2));
        assert_eq!(cidr.netmask(), Ipv4Addr::new(255, 255, 255, 0));
    }

    #[test]
    fn rejects_invalid_prefix() {
        let err =
            Ipv4Cidr::parse("10.118.0.2/33").expect_err("CIDR should reject prefixes over 32");
        assert!(err.to_string().contains("at most 32"));
    }
}
