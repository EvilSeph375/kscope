use tokio::net::UdpSocket;
use std::net::SocketAddr;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Сервер слушает на порту 51820
    let addr = "0.0.0.0:51820";
    let socket = UdpSocket::bind(addr).await?;
    println!("Echo server listening on {}", addr);
    
    let mut buf = [0u8; 1500];
    
    loop {
        match socket.recv_from(&mut buf).await {
            Ok((n, src_addr)) => {
                println!("Received {} bytes from {}", n, src_addr);
                
                // Отправляем данные обратно (эхо)
                if let Err(e) = socket.send_to(&buf[..n], src_addr).await {
                    eprintln!("Failed to send echo: {}", e);
                }
            }
            Err(e) => {
                eprintln!("Error receiving: {}", e);
                break;
            }
        }
    }
    
    Ok(())
}
