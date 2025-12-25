use kscope::tun::{TunDevice, TunConfig};
use std::net::Ipv4Addr;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== KScope Simple TUN Test ===");
    
    let config = TunConfig {
        name: "kscope0".to_string(),
        ip: "10.0.0.2".parse()?,
        prefix_len: 24,
        mtu: 1420,
    };
    
    println!("Creating TUN interface '{}' with IP {}...", 
             config.name, config.ip);
    
    match TunDevice::create(config) {
        Ok(mut tun) => {
            println!("✅ TUN interface created successfully!");
            println!("   Interface name: {}", tun.name());
            
            // Тестируем запись пакета
            println!("\nTesting packet write...");
            let test_packet = create_test_packet();
            
            match tun.write(&test_packet) {
                Ok(_) => println!("✅ Test packet written ({} bytes)", test_packet.len()),
                Err(e) => println!("❌ Failed to write: {}", e),
            }
            
            // Попробуем прочитать
            println!("\nTrying to read (waiting 1 second)...");
            
            // Устанавливаем простой таймаут
            let start = std::time::Instant::now();
            let timeout = std::time::Duration::from_secs(1);
            
            let mut received = false;
            while start.elapsed() < timeout {
                match tun.read() {
                    Ok(packet) => {
                        println!("✅ Received packet: {} bytes", packet.len());
                        if packet == test_packet {
                            println!("   → This is our test packet!");
                        }
                        received = true;
                        break;
                    }
                    Err(e) => {
                        // Просто продолжаем ждать
                        std::thread::sleep(std::time::Duration::from_millis(10));
                        continue;
                    }
                }
            }
            
            if !received {
                println!("ℹ️  No packets received (timeout)");
            }
            
            println!("\n=== TUN Interface Ready ===");
            println!("Name: {}", tun.name());
            println!("MTU: {}", tun.mtu());
            println!("\nKeep the interface alive for testing...");
            println!("Press Ctrl+C to exit.");
            
            loop {
                std::thread::sleep(std::time::Duration::from_secs(10));
            }
        }
        Err(e) => {
            println!("❌ Failed to create TUN interface: {}", e);
            println!("\nTroubleshooting:");
            println!("1. Run with sudo: sudo target/debug/examples/simple_tun");
            println!("2. Check tun module: sudo lsmod | grep tun");
            println!("3. Load tun module: sudo modprobe tun");
            println!("4. Check permissions: ls -la /dev/net/tun");
            return Ok(());
        }
    }
}

fn create_test_packet() -> Vec<u8> {
    vec![
        0x45, 0x00, 0x00, 0x54,
        0x00, 0x00, 0x40, 0x00,
        0x40, 0x01, 0x00, 0x00,
        0xc0, 0xa8, 0x01, 0x64,
        0x08, 0x08, 0x08, 0x08,
        0x08, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x00,
        0x61, 0x62, 0x63, 0x64,
        0x65, 0x66, 0x67, 0x68,
        0x69, 0x6a, 0x6b, 0x6c,
        0x6d, 0x6e, 0x6f, 0x70,
        0x71, 0x72, 0x73, 0x74,
        0x75, 0x76, 0x77, 0x61,
        0x62, 0x63, 0x64, 0x65,
        0x66, 0x67, 0x68, 0x69,
    ]
}
