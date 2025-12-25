// examples/test_tun.rs
use kscope::tun::{TunDevice, TunConfig};
use std::net::Ipv4Addr;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Включаем логирование
    env_logger::init();
    
    println!("=== KScope TUN Interface Test ===");
    
    // Создаём конфигурацию TUN
    let config = TunConfig {
        name: "kscope0".to_string(),
        ip: "10.0.0.2".parse()?,
        prefix_len: 24,
        mtu: 1420,
    };
    
    println!("Creating TUN interface '{}' with IP {}...", 
             config.name, config.ip);
    
    let mut tun = TunDevice::create(config)?;
    
    println!("TUN interface created successfully!");
    println!("Interface name: {}", tun.name());
    
    // Создаём тестовый IP-пакет (упрощённый IPv4 пакет)
    let test_packet = create_test_ipv4_packet();
    println!("\nCreated test IPv4 packet: {} bytes", test_packet.len());
    
    // Отправляем пакет в TUN
    println!("Writing packet to TUN...");
    tun.write(&test_packet)?;
    
    println!("Packet written successfully!");
    
    // Пробуем прочитать пакет (в реальном VPN здесь будут читаться пакеты из сети)
    println!("\nAttempting to read from TUN (press Ctrl+C to stop)...");
    
    let mut packet_count = 0;
    loop {
        match tun.read() {
            Ok(packet) => {
                packet_count += 1;
                println!("Packet #{} received: {} bytes", packet_count, packet.len());
                
                // Проверяем, не наш ли это тестовый пакет
                if packet == test_packet {
                    println!("  → This is our test packet!");
                }
                
                // Простой анализ IP-пакета
                if packet.len() >= 20 {
                    let version = packet[0] >> 4;
                    let protocol = packet[9];
                    let src_ip = format!("{}.{}.{}.{}", 
                        packet[12], packet[13], packet[14], packet[15]);
                    let dst_ip = format!("{}.{}.{}.{}", 
                        packet[16], packet[17], packet[18], packet[19]);
                    
                    println!("  → IPv{} | Protocol: {} | Src: {} → Dst: {}", 
                            version, protocol, src_ip, dst_ip);
                }
            }
            Err(e) => {
                eprintln!("Error reading from TUN: {}", e);
                break;
            }
        }
        
        // Читаем не слишком быстро
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    
    // Автоматически закроется при Drop
    println!("\nTest completed.");
    Ok(())
}

/// Создаёт упрощённый IPv4 пакет для тестирования
fn create_test_ipv4_packet() -> Vec<u8> {
    let mut packet = Vec::new();
    
    // IPv4 заголовок (20 байт)
    // Version (4) + IHL (5) = 0x45
    packet.push(0x45);                     // Version + IHL
    packet.push(0x00);                     // DSCP + ECN
    packet.extend(&(20 + 32).to_be_bytes()[2..]); // Total Length (52 bytes)
    packet.extend(&[0x00, 0x00]);          // Identification
    packet.extend(&[0x40, 0x00]);          // Flags + Fragment Offset
    packet.push(0x40);                     // TTL (64)
    packet.push(0x06);                     // Protocol (TCP = 6)
    packet.extend(&[0x00, 0x00]);          // Header Checksum (0 для простоты)
    
    // Source IP: 192.168.1.100
    packet.extend(&[192, 168, 1, 100]);
    
    // Destination IP: 8.8.8.8 (Google DNS)
    packet.extend(&[8, 8, 8, 8]);
    
    // TCP заголовок (20 байт) + данные (32 байта) для примера
    for i in 0..52 {
        packet.push((i % 256) as u8);
    }
    
    packet
}
