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
    /// Создаёт TUN-интерфейс и настраивает его
    pub fn create(config: TunConfig) -> Result<Self> {
        // Создаём TUN интерфейс
        let iface = Iface::without_packet_info(&config.name, tun_tap::Mode::Tun)
            .map_err(|e| KScopeError::Io(e))?;
        
        let device = Self {
            iface,
            config: config.clone(),
            mtu: config.mtu as usize,
        };
        
        // Настраиваем интерфейс через системные команды
        device.configure_interface()?;
        
        Ok(device)
    }
    
    /// Настраивает IP, MTU и включает интерфейс
    fn configure_interface(&self) -> Result<()> {
        let cidr = format!("{}/{}", self.config.ip, self.config.prefix_len);
        
        // Устанавливаем IP адрес
        let status = Command::new("ip")
            .args(["addr", "add", &cidr, "dev", &self.config.name])
            .status()
            .map_err(|e| {
                println!("⚠️  Failed to run 'ip' command: {}", e);
                KScopeError::Io(e)
            })?;
        
        if !status.success() {
            println!("⚠️  Failed to set IP address on {} (might already be set)", self.config.name);
        }
        
        // Включаем интерфейс
        Command::new("ip")
            .args(["link", "set", "up", "dev", &self.config.name])
            .status()
            .map_err(|e| KScopeError::Io(e))?;
        
        // Устанавливаем MTU
        Command::new("ip")
            .args(["link", "set", "mtu", &self.config.mtu.to_string(), "dev", &self.config.name])
            .status()
            .map_err(|e| KScopeError::Io(e))?;
        
        println!("✅ TUN interface {} configured: {} (MTU: {})", 
                 self.config.name, cidr, self.config.mtu);
        
        Ok(())
    }
    
    /// Читает пакет из TUN устройства
    pub fn read(&mut self) -> Result<Vec<u8>> {
        let mut buffer = vec![0u8; self.mtu + 4];
        
        match self.iface.recv(&mut buffer) {
            Ok(n) => {
                if n < 4 {
                    return Err(KScopeError::Io(io::Error::new(
                        io::ErrorKind::UnexpectedEof, 
                        "Packet too small"
                    )));
                }
                Ok(buffer[4..n].to_vec())
            }
            Err(e) => Err(KScopeError::Io(e)),
        }
    }
    
    /// Отправляет пакет в TUN устройство
    pub fn write(&mut self, packet: &[u8]) -> Result<()> {
        let mut buffer = Vec::with_capacity(packet.len() + 4);
        
        buffer.extend_from_slice(&[0u8, 0u8]);          // Флаги TUN
        buffer.extend_from_slice(&[0x08u8, 0x00u8]);   // Протокол IPv4
        buffer.extend_from_slice(packet);              // Данные
        
        self.iface.send(&buffer)
            .map_err(|e| KScopeError::Io(e))?;
        
        Ok(())
    }
    
    /// Возвращает имя интерфейса
    pub fn name(&self) -> &str {
        &self.config.name
    }
    
    /// Возвращает MTU
    pub fn mtu(&self) -> u16 {
        self.config.mtu
    }
    
    /// Удаляет TUN интерфейс
    pub fn close(self) -> Result<()> {
        let _ = Command::new("ip")
            .args(["link", "delete", "dev", &self.config.name])
            .status();
        Ok(())
    }
}
