// Удаляем неиспользуемый импорт
// use crate::Result;

pub mod device;

// Переносим объявления структур в mod.rs
#[derive(Debug, Clone)]
pub struct TunConfig {
    pub name: String,
    pub address: String,  // В формате "10.0.0.1/24"
    pub mtu: u16,
    pub persistent: bool,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            name: "kscope0".to_string(),
            address: "10.0.0.1/24".to_string(),
            mtu: 1420,
            persistent: false,
        }
    }
}

/// Результат чтения из TUN устройства
#[derive(Debug)]
pub struct TunPacket {
    pub data: Vec<u8>,
    pub protocol: u16,  // Ethernet type (0x0800 for IPv4, 0x86DD for IPv6)
}

impl TunPacket {
    pub fn new(data: Vec<u8>, protocol: u16) -> Self {
        Self { data, protocol }
    }
    
    pub fn is_ipv4(&self) -> bool {
        self.protocol == 0x0800
    }
    
    pub fn is_ipv6(&self) -> bool {
        self.protocol == 0x86DD
    }
}

// Реэкспорт
pub use device::TunDevice;
pub use device::ip_utils;
pub use device::route;
