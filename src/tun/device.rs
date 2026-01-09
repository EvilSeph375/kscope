use std::io;
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

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            name: "kscope0".to_string(),
            ip: "10.0.0.1".parse().expect("Valid IP"),
            prefix_len: 24,
            mtu: 1500,
        }
    }
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

        let status = Command::new("ip")
            .args(["addr", "add", &cidr, "dev", &self.config.name])
            .status()
            .map_err(|e| KScopeError::Io(e.to_string()))?;

        if !status.success() {
            println!("⚠️  IP address may already exist on {}", self.config.name);
        }

        Command::new("ip")
            .args(["link", "set", "up", "dev", &self.config.name])
            .status()
            .map_err(|e| KScopeError::Io(e.to_string()))?;

        Command::new("ip")
            .args(["link", "set", "mtu", &self.config.mtu.to_string(), "dev", &self.config.name])
            .status()
            .map_err(|e| KScopeError::Io(e.to_string()))?;

        println!("✅ TUN {} configured: {} (MTU {})",
                 self.config.name, cidr, self.config.mtu);

        Ok(())
    }

    pub fn read(&mut self) -> Result<Vec<u8>> {
        let mut buffer = vec![0u8; self.mtu + 4];

        match self.iface.recv(&mut buffer) {
            Ok(n) => {
                if n < 4 {
                    return Err(KScopeError::Io("Packet too small".to_string()));
                }

                Ok(buffer[4..n].to_vec())
            }
            Err(e) => Err(KScopeError::Io(e.to_string())),
        }
    }

    pub fn write(&mut self, packet: &[u8]) -> Result<()> {
        let protocol: u16 = if !packet.is_empty() && (packet[0] >> 4) == 4 {
            0x0800
        } else {
            0x0000
        };

        let mut buffer = Vec::with_capacity(packet.len() + 4);
        buffer.extend_from_slice(&[0, 0]);
        buffer.extend_from_slice(&protocol.to_be_bytes());
        buffer.extend_from_slice(packet);

        let _ = self.iface.send(&buffer);
        Ok(())
    }

    pub fn name(&self) -> &str {
        &self.config.name
    }

    pub fn mtu(&self) -> u16 {
        self.config.mtu
    }

    pub fn ip(&self) -> Ipv4Addr {
        self.config.ip
    }

    pub fn close(self) -> Result<()> {
        let _ = Command::new("ip")
            .args(["link", "delete", "dev", &self.config.name])
            .status();
        Ok(())
    }

    pub fn create_test() -> Result<Self> {
        let config = TunConfig {
            name: "kscope0".to_string(),
            ip: "10.0.0.2".parse()
                .map_err(|e| KScopeError::Config(format!("Invalid IP: {}", e)))?,
            prefix_len: 24,
            mtu: 1420,
        };

        Self::create(config)
    }
}
