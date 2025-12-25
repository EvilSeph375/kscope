// src/network/mod.rs
pub mod udp;

use crate::Result;
use std::net::SocketAddr;

/// Обработчик входящих пакетов
pub trait PacketHandler: Send + Sync {
    fn handle_packet(&mut self, source: SocketAddr, data: &[u8]) -> Result<Option<Vec<u8>>>;
}

/// Простой эхо-обработчик для тестирования
pub struct EchoHandler {
    packet_count: u64,
}

impl EchoHandler {
    pub fn new() -> Self {
        Self { packet_count: 0 }
    }
}

impl PacketHandler for EchoHandler {
    fn handle_packet(&mut self, source: SocketAddr, data: &[u8]) -> Result<Option<Vec<u8>>> {
        self.packet_count += 1;
        println!("[UDP] Packet #{} from {}: {} bytes", 
                 self.packet_count, source, data.len());
        
        // Эхо - отправляем обратно те же данные
        Ok(Some(data.to_vec()))
    }
}
