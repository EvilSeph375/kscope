// examples/tun_final_test.rs
use kscope::tun::{TunDevice, TunConfig};
use std::thread;
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Final TUN Test ===");
    
    // Удаляем старый интерфейс
    let _ = std::process::Command::new("ip")
        .args(["link", "delete", "dev", "kscope0"])
        .status();
    
    thread::sleep(Duration::from_millis(500));
    
    // Создаем конфиг
    let config = TunConfig {
        name: "kscope0".to_string(),
        ip: "10.0.0.2".parse()?,
        prefix_len: 24,
        mtu: 1420,
    };
    
    println!("Creating TUN interface...");
    let tun = TunDevice::create(config)?;
    println!("✅ TUN interface created: {}", tun.name());
    
    // Проверяем, что интерфейс существует в системе
    println!("\nChecking system interface...");
    let output = std::process::Command::new("ip")
        .args(["addr", "show", "kscope0"])
        .output()?;
    
    if output.status.success() {
        println!("✅ Interface exists in system:");
        println!("{}", String::from_utf8_lossy(&output.stdout));
    } else {
        println!("❌ Interface NOT found in system");
        return Ok(());
    }
    
    // Клонируем TUN для отправки пакетов
    let mut tun_for_write = tun;
    
    // Тест 1: Пробуем отправить сырые байты (без TUN заголовка)
    println!("\nTest 1: Sending raw bytes...");
    let raw_bytes = vec![0x00u8; 64];
    
    match tun_for_write.write(&raw_bytes) {
        Ok(_) => println!("✅ Raw bytes sent"),
        Err(e) => println!("❌ Failed: {}", e),
    }
    
    // Тест 2: Пробуем с правильным TUN заголовком
    println!("\nTest 2: Sending with TUN header...");
    let mut packet_with_header = Vec::new();
    packet_with_header.extend_from_slice(&[0x00, 0x00]); // Flags
    packet_with_header.extend_from_slice(&[0x08, 0x00]); // Protocol: IPv4
    packet_with_header.extend_from_slice(&[0x45, 0x00, 0x00, 0x1c]); // Minimal IPv4
    packet_with_header.extend_from_slice(&vec![0x00u8; 20]); // Остальные байты
    
    match tun_for_write.write(&packet_with_header) {
        Ok(_) => println!("✅ Packet with header sent"),
        Err(e) => println!("❌ Failed: {}", e),
    }
    
    // Тест 3: Используем внутренний метод iface.send напрямую (для диагностики)
    println!("\nTest 3: Testing with different packet sizes...");
    
    let test_sizes = [14, 28, 46, 60, 128, 256, 512];
    for size in test_sizes.iter() {
        let test_packet = vec![0xAAu8; *size];
        
        match tun_for_write.write(&test_packet) {
            Ok(_) => println!("✅ {} bytes: OK", size),
            Err(e) => println!("❌ {} bytes: {}", size, e),
        }
        
        thread::sleep(Duration::from_millis(50));
    }
    
    // Тест 4: Чтение
    println!("\nTest 4: Reading packets for 5 seconds...");
    let start = std::time::Instant::now();
    let mut packet_count = 0;
    
    while start.elapsed() < Duration::from_secs(5) {
        match tun_for_write.read() {
            Ok(packet) => {
                packet_count += 1;
                print!("📦 ");
                if packet_count % 10 == 0 {
                    println!("Packet {}: {} bytes", packet_count, packet.len());
                }
            }
            Err(_) => {
                thread::sleep(Duration::from_millis(1));
            }
        }
    }
    
    println!("\nTotal packets received: {}", packet_count);
    
    // Держим интерфейс открытым
    println!("\n=== Interface Ready ===");
    println!("TUN interface {} is active.", tun_for_write.name());
    println!("Open another terminal and test:");
    println!("  sudo tcpdump -i kscope0 -vv");
    println!("  sudo ping -I kscope0 8.8.8.8");
    println!("\nPress Ctrl+C to close interface");
    
    // Бесконечный цикл чтобы интерфейс не закрылся
    loop {
        thread::sleep(Duration::from_secs(10));
        println!("[Heartbeat] Interface still active...");
    }
}
