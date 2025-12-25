use kscope::tun::{TunDevice, TunConfig};
use std::process::Command;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== KScope Complete TUN Test ===");
    
    // 1. Сначала удаляем старый интерфейс, если он существует
    cleanup_interface("kscope0");
    
    // 2. Создаём новый интерфейс
    let config = TunConfig {
        name: "kscope0".to_string(),
        ip: "10.0.0.2".parse()?,
        prefix_len: 24,
        mtu: 1420,
    };
    
    println!("Creating TUN interface '{}' with IP {}...", 
             config.name, config.ip);
    
    let mut tun = match TunDevice::create(config) {
        Ok(tun) => {
            println!("✅ TUN interface created successfully!");
            tun
        }
        Err(e) => {
            println!("❌ Failed to create TUN: {}", e);
            println!("Trying to force cleanup and retry...");
            
            // Пытаемся принудительно удалить интерфейс
            let _ = Command::new("sudo")
                .args(["ip", "link", "delete", "dev", "kscope0"])
                .status();
            
            std::thread::sleep(std::time::Duration::from_secs(1));
            
            // Пробуем снова
            TunDevice::create(TunConfig {
                name: "kscope0".to_string(),
                ip: "10.0.0.2".parse()?,
                prefix_len: 24,
                mtu: 1420,
            })?
        }
    };
    
    println!("   Interface name: {}", tun.name());
    println!("   MTU: {}", tun.mtu());
    
    // 3. Тестируем запись и чтение
    test_packet_io(&mut tun);
    
    // 4. Демонстрация работы интерфейса
    println!("\n=== TUN Interface Demo ===");
    println!("Interface {} is ready!", tun.name());
    println!("\nYou can test it in another terminal:");
    println!("  sudo tcpdump -i kscope0 -n");
    println!("  sudo ping -I kscope0 10.0.0.1");
    println!("\nPress Ctrl+C to clean up and exit.");
    
    // 5. Держим интерфейс активным
    let mut counter = 0;
    loop {
        // Периодически отправляем тестовые пакеты
        if counter % 10 == 0 {
            match tun.write(&create_test_packet()) {
                Ok(_) => println!("📤 Sent test packet"),
                Err(e) => println!("❌ Failed to send: {}", e),
            }
        }
        
        // Пробуем читать
        match tun.read() {
            Ok(packet) => {
                println!("📦 Received packet: {} bytes", packet.len());
                analyze_packet(&packet);
            }
            Err(_) => {
                // Ничего не пришло, это нормально
            }
        }
        
        std::thread::sleep(std::time::Duration::from_millis(100));
        counter += 1;
    }
}

fn cleanup_interface(name: &str) {
    println!("Cleaning up old interface '{}'...", name);
    let _ = Command::new("ip")
        .args(["link", "delete", "dev", name])
        .status();
    
    // Дадим время на очистку
    std::thread::sleep(std::time::Duration::from_millis(500));
}

fn test_packet_io(tun: &mut TunDevice) {
    println!("\n=== Testing Packet I/O ===");
    
    // Тест записи
    let test_packet = create_test_packet();
    println!("Sending test packet ({} bytes)...", test_packet.len());
    
    match tun.write(&test_packet) {
        Ok(_) => println!("✅ Packet sent successfully"),
        Err(e) => println!("❌ Failed to send: {}", e),
    }
    
    // Тест чтения с таймаутом
    println!("Waiting for incoming packets (2 seconds)...");
    let start = std::time::Instant::now();
    
    while start.elapsed() < std::time::Duration::from_secs(2) {
        match tun.read() {
            Ok(packet) => {
                println!("✅ Received packet: {} bytes", packet.len());
                if packet == test_packet {
                    println!("   → This is our echoed test packet!");
                }
                return;
            }
            Err(_) => {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        }
    }
    
    println!("ℹ️  No packets received (expected - nothing is sending to us)");
}

fn analyze_packet(packet: &[u8]) {
    if packet.len() < 20 {
        println!("   Too small for IP analysis");
        return;
    }
    
    let version = packet[0] >> 4;
    if version == 4 {
        // IPv4
        let protocol = packet[9];
        let src = format!("{}.{}.{}.{}", packet[12], packet[13], packet[14], packet[15]);
        let dst = format!("{}.{}.{}.{}", packet[16], packet[17], packet[18], packet[19]);
        
        let proto_str = match protocol {
            1 => "ICMP",
            6 => "TCP",
            17 => "UDP",
            _ => "Unknown",
        };
        
        println!("   IPv4: {} → {} | Proto: {}", src, dst, proto_str);
    }
}

fn create_test_packet() -> Vec<u8> {
    // Корректный ICMP echo request (ping)
    let mut packet = Vec::new();
    
    // IPv4 заголовок (20 байт)
    // Version=4, IHL=5 (20 bytes header)
    packet.push(0x45);                     // Version + IHL
    packet.push(0x00);                     // DSCP + ECN
    packet.extend(&[0x00, 0x3C]);          // Total Length: 60 bytes (20 + 8 + 32)
    packet.extend(&[0x00, 0x01]);          // Identification
    packet.extend(&[0x00, 0x00]);          // Flags + Fragment Offset
    packet.push(0x40);                     // TTL: 64
    packet.push(0x01);                     // Protocol: ICMP (1)
    packet.extend(&[0x00, 0x00]);          // Header Checksum (пока 0)
    
    // Source IP: 10.0.0.2 (наш TUN интерфейс)
    packet.extend(&[10, 0, 0, 2]);
    
    // Destination IP: 8.8.8.8 (Google DNS)
    packet.extend(&[8, 8, 8, 8]);
    
    // ICMP Echo Request (8 байт + 32 байта данных)
    packet.push(0x08);                     // Type: Echo Request
    packet.push(0x00);                     // Code: 0
    packet.extend(&[0x00, 0x00]);          // Checksum (пока 0)
    packet.extend(&[0x00, 0x01]);          // Identifier
    packet.extend(&[0x00, 0x01]);          // Sequence Number
    
    // Данные (32 байта)
    for i in 0..32 {
        packet.push((i % 256) as u8);
    }
    
    // Рассчитываем checksum для ICMP
    let icmp_checksum = calculate_checksum(&packet[20..]);
    packet[22] = (icmp_checksum >> 8) as u8;
    packet[23] = (icmp_checksum & 0xFF) as u8;
    
    // Рассчитываем checksum для IP
    let ip_checksum = calculate_checksum(&packet[0..20]);
    packet[10] = (ip_checksum >> 8) as u8;
    packet[11] = (ip_checksum & 0xFF) as u8;
    
    packet
}

fn calculate_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    
    // Складываем 16-битные слова
    for chunk in data.chunks(2) {
        let word = if chunk.len() == 2 {
            ((chunk[0] as u16) << 8) | (chunk[1] as u16)
        } else {
            (chunk[0] as u16) << 8
        };
        sum += word as u32;
    }
    
    // Добавляем перенос
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    !(sum as u16)
}
