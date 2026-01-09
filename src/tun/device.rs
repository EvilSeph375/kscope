use std::net::Ipv4Addr;
use std::process::Command;
use tun_tap::Iface;
use crate::{Result, KScopeError};

#[derive(Debug, Clone)]
pub struct TunConfig {
    pub name: String,
    pub ip: Ipv4Addr,
    pub prefix_len: u8,
    pub mtu: u16,
}

pub struct TunDevice {
    iface: Iface,
    mtu: usize,
}

impl TunDevice {
    pub fn create(config: TunConfig) -> Result<Self> {
        let iface = Iface::without_packet_info(&config.name, tun_tap::Mode::Tun)
            .map_err(|e| KScopeError::Io(e.to_string()))?;

        let cidr = format!("{}/{}", config.ip, config.prefix_len);

        Command::new("ip")
            .args(["addr", "add", &cidr, "dev", &config.name])
            .status()
            .ok();

        Command::new("ip")
            .args(["link", "set", "up", "dev", &config.name])
            .status()
            .ok();

        Command::new("ip")
            .args(["link", "set", "mtu", &config.mtu.to_string(), "dev", &config.name])
            .status()
            .ok();

        println!("✅ TUN {} configured: {}", config.name, cidr);

        Ok(Self {
            iface,
            mtu: config.mtu as usize,
        })
    }

    pub fn read(&mut self) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; self.mtu];
        let n = self.iface.recv(&mut buf)
            .map_err(|e| KScopeError::Io(e.to_string()))?;
        buf.truncate(n);
        Ok(buf)
    }

    pub fn write(&mut self, data: &[u8]) -> Result<()> {
        self.iface.send(data)
            .map_err(|e| KScopeError::Io(e.to_string()))?;
        Ok(())
    }
}
