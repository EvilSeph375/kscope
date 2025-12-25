// examples/udp_test_client.rs
use kscope::network::{EchoHandler, udp::UdpTransport};
use kscope::Result;
use std::time::Duration;
use tokio::time;

#[tokio::main]
async fn main() -> Result<()> {
    println!("=== KScope UDP Test Client ===");
    
    // Создаем простой эхо-обработчик
    let handler = Box::new(EchoHandler::new());
    
    // Подключаемся к серверу
    println!("Connecting to UDP server...");
    let transport = UdpTransport::connect("127.0.0.1:51820", handler).await?;
    
    println!("✅ Connected to server");
    println!("Local address: {}", transport.local_addr()?);
    
    // Отправляем тестовые пакеты
    println!("\nSending test packets...");
    
    for i in 1..=5 {
        let message = format!("Test packet #{} from KScope VPN", i);
        
        println!("Sending: '{}'", message);
        
        match transport.send(message.as_bytes()).await {
            Ok(size) => println!("  ✅ Sent {} bytes", size),
            Err(e) => println!("  ❌ Failed: {}", e),
        }
        
        // Ждем немного между пакетами
        time::sleep(Duration::from_secs(1)).await;
    }
    
    println!("\n=== Test Complete ===");
    
    Ok(())
}
