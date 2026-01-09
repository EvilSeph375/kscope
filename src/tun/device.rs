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
    config: TunConfig,
    mtu: usize,
}

impl TunDevice {
    pub fn create(config: TunConfig) -> Result<Self> {
        let iface = Iface::without_packet_info(&config.name, tun_tap::Mode::Tun)
            .map_err(|e| KScopeError::Io(e.to_string()))?;

        let device = Self {
            iface,
            config: config.clone(),
            mtu: config.mtu as usize,
        };

        device.configure_interface()?;
        Ok(device)
    }

    fn configure_interface(&self) -> Result<()> {
        let cidr = format!("{}/{}", self.config.ip, self.config.prefix_len);

        let _ = Command::new("ip")
            .args(["addr", "add", &cidr, "dev", &self.config.name])
            .status();

        Command::new("ip")
            .args(["link", "set", "dev", &self.config.name, "up"])
            .status()
            .map_err(|e| KScopeError::Io(e.to_string()))?;

        Command::new("ip")
            .args(["link", "set", "mtu", &self.config.mtu.to_string(), "dev", &self.config.name])
            .status()
            .map_err(|e| KScopeError::Io(e.to_string()))?;

        println!("✅ TUN {} configured: {}", self.config.name, cidr);
        Ok(())
    }

    pub fn read(&mut self) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; self.mtu];
        let n = self.iface.recv(&mut buf).map_err(|e| KScopeError::Io(e.to_string()))?;
        Ok(buf[..n].to_vec())
    }

    pub fn write(&mut self, data: &[u8]) -> Result<()> {
        self.iface.send(data).map_err(|e| KScopeError::Io(e.to_string()))?;
        Ok(())
    }
}
