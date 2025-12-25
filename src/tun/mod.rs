// src/tun/mod.rs
pub mod device;
pub mod route;  // Добавляем эту строку

pub use device::{TunDevice, TunConfig};
pub use route::{add_default_route, add_route};  // И эту

#[derive(Debug)]
pub struct TunPacket {
    pub data: Vec<u8>,
    pub protocol: u16,
}

impl TunPacket {
    pub fn new(data: Vec<u8>, protocol: u16) -> Self {
        Self { data, protocol }
    }
}
