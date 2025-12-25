use kscope::tun::{TunDevice, TunConfig};
use std::time::Duration;
use std::thread;

fn main() -> anyhow::Result<()> {
    println!("=== KScope TUN Interface Test ===");
    
    // Конфигурация TUN
    let config = TunConfig {
        name: "kscope0".to_string(),
        address: "10.0.0.2/24".to_string(),
        mtu: 1420,
        persistent: false,
    };
    
    println!("Creating TUN interface {}...", config.name);
    
    // Создаем TUN устройство
    let mut tun = match TunDevice::create(config) {
        Ok(tun) => tun,
        Err(e) => {
            eprintln!("Failed to create TUN interface: {}", e);
            eprintln!("Note: This requires root privileges or NET_ADMIN capability.");
            eprintln!("Try: sudo target/debug/examples/test_tun");
            return Ok(());
        }
    };
    
    println!("TUN interface created successfully!");
    println!("  Name: {}", tun.name());
    println!("  MTU: {}", tun.mtu());
    
    // Пытаемся получить IP
    match tun.ip_address() {
        Ok(ip) => println!("  IP: {}/24", ip),
        Err(e) => println!("  IP: Could not determine ({})", e),
    }
    
    println!("\nReading packets for 30 seconds...");
    println!("Try pinging the interface from another terminal:");
    println!("  $ ping 10.0.0.2");
    println!("\nPress Ctrl+C to stop earlier.\n");
    
    // Читаем пакеты в течение 30 секунд
    let start = std::time::Instant::now();
    let mut packet_count = 0;
    
    while start.elapsed() < Duration::from_secs(30) {
        // Читаем с таймаутом 100ms
        match tun.read_timeout(100) {
            Ok(Some(packet)) => {
                packet_count += 1;
                
                let src = kscope::tun::ip_utils::get_source_ip(&packet.data);
                let dst = kscope::tun::ip_utils::get_destination_ip(&packet.data);
                let proto = kscope::tun::ip_utils::get_ip_protocol(&packet.data);
                
                println!("Packet #{}: {} -> {} (proto: {:?}, len: {})",
                    packet_count,
                    src.unwrap_or_else(|| "?".to_string()),
                    dst.unwrap_or_else(|| "?".to_string()),
                    proto.map(|p| format!("0x{:02x}", p)),
                    packet.data.len()
                );
            }
            Ok(None) => {
                // Таймаут - ничего не пришло
                if packet_count == 0 && start.elapsed() > Duration::from_secs(5) {
                    print!(".");
                    std::io::Write::flush(&mut std::io::stdout()).unwrap();
                }
            }
            Err(e) => {
                eprintln!("\nError reading packet: {}", e);
                break;
            }
        }
    }
    
    println!("\n\nTest completed.");
    println!("Received {} packets in {} seconds.", 
        packet_count, 
        start.elapsed().as_secs()
    );
    
    // Закрываем TUN
    let _ = tun.close();
    println!("TUN interface closed.");
    
    Ok(())
}
