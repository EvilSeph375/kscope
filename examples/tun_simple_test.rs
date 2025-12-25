// examples/tun_simple_test.rs
use kscope::tun::{TunDevice, TunConfig};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Simple TUN Test ===");
    
    // Удаляем старый интерфейс
    let _ = std::process::Command::new("ip")
        .args(["link", "delete", "dev", "kscope0"])
        .status();
    
    // Создаем конфиг
    let config = TunConfig {
        name: "kscope0".to_string(),
        ip: "10.0.0.2".parse()?,
        prefix_len: 24,
        mtu: 1420,
    };
    
    println!("Creating TUN interface...");
    let mut tun = TunDevice::create(config)?;
    println!("✅ TUN interface created: {}", tun.name());
    
    // Тест 1: Простой ARP пакет (всегда работает)
    println!("\nTest 1: Sending ARP packet...");
    let arp_packet = hex::decode("ffffffffffff0a00000208080600010800060400010a00000208000000000008080808").unwrap();
    
    match tun.write(&arp_packet) {
        Ok(_) => println!("✅ ARP packet sent successfully"),
        Err(e) => println!("❌ Failed to send ARP: {}", e),
    }
    
    // Тест 2: Чтение
    println!("\nTest 2: Reading for 3 seconds...");
    let start = std::time::Instant::now();
    let mut packet_count = 0;
    
    while start.elapsed() < std::time::Duration::from_secs(3) {
        match tun.read() {
            Ok(packet) => {
                packet_count += 1;
                println!("📦 Packet {}: {} bytes", packet_count, packet.len());
                
                // Определяем тип пакета
                if packet.len() >= 14 {
                    let ethertype = u16::from_be_bytes([packet[12], packet[13]]);
                    match ethertype {
                        0x0800 => println!("  Type: IPv4"),
                        0x0806 => println!("  Type: ARP"),
                        0x86DD => println!("  Type: IPv6"),
                        _ => println!("  Type: Unknown (0x{:04x})", ethertype),
                    }
                }
            }
            Err(_) => {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        }
    }
    
    if packet_count == 0 {
        println!("ℹ️  No packets received");
    }
    
    println!("\n=== Test Complete ===");
    println!("Interface {} is ready for use.", tun.name());
    println!("Check with: sudo ip addr show kscope0");
    
    Ok(())
}
