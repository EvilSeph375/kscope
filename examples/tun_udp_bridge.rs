// examples/tun_udp_bridge.rs
use kscope::tun::TunDevice;
use kscope::network::{PacketHandler, udp::UdpTransport};
use kscope::Result;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

/// Мост между TUN интерфейсом и UDP сокетом
struct TunUdpBridge {
    tun: Arc<Mutex<TunDevice>>,
}

impl TunUdpBridge {
    fn new(tun: TunDevice) -> Self {
        Self {
            tun: Arc::new(Mutex::new(tun)),
        }
    }
}

impl PacketHandler for TunUdpBridge {
    fn handle_packet(&mut self, source: SocketAddr, data: &[u8]) -> Result<Option<Vec<u8>>> {
        println!("[UDP→TUN] From {}: {} bytes", source, data.len());
        
        // Пишем полученные данные в TUN интерфейс
        let mut tun = self.tun.lock().unwrap();
        
        if let Err(e) = tun.write_ignore_errors(data) {
            eprintln!("[UDP→TUN] Failed to write to TUN: {}", e);
        } else {
            println!("[UDP→TUN] Written to TUN interface");
        }
        
        // Не отправляем ответ (это будет делать TUN сторона если нужно)
        Ok(None)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    println!("=== KScope TUN-UDP Bridge ===");
    
    // 1. Создаем TUN интерфейс
    println!("Creating TUN interface...");
    let tun = TunDevice::create_test()?;
    println!("✅ TUN interface created: {}", tun.name());
    
    // 2. Создаем UDP транспорт с мостом
    let bridge = TunUdpBridge::new(tun);
    let handler = Box::new(bridge);
    
    println!("Starting UDP bridge on 0.0.0.0:51820...");
    let mut transport = UdpTransport::bind("0.0.0.0:51820", handler).await?;
    
    println!("\n=== Bridge Ready ===");
    println!("Listening on UDP port 51820");
    println!("Local address: {}", transport.local_addr()?);
    println!("Press Ctrl+C to stop");
    
    // 3. Запускаем обработку
    transport.run().await?;
    
    Ok(())
}
