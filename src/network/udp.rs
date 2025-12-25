// src/network/udp.rs
use crate::{Result, KScopeError};
use crate::network::PacketHandler;
use std::net::SocketAddr;
use tokio::net::UdpSocket;

/// UDP транспорт для клиент-серверного взаимодействия
pub struct UdpTransport {
    socket: UdpSocket,
    handler: Box<dyn PacketHandler>,
}

impl UdpTransport {
    /// Создает сервер, который слушает на указанном адресе
    pub async fn bind(addr: &str, handler: Box<dyn PacketHandler>) -> Result<Self> {
        let socket = UdpSocket::bind(addr).await
            .map_err(|e| KScopeError::Io(e))?;
        
        println!("[UDP] Server listening on {}", addr);
        Ok(Self { socket, handler })
    }
    
    /// Создает клиент, который подключается к серверу
    pub async fn connect(server_addr: &str, handler: Box<dyn PacketHandler>) -> Result<Self> {
        let socket = UdpSocket::bind("0.0.0.0:0").await
            .map_err(|e| KScopeError::Io(e))?;
        
        socket.connect(server_addr).await
            .map_err(|e| KScopeError::Io(e))?;
        
        println!("[UDP] Client connected to {}", server_addr);
        Ok(Self { socket, handler })
    }
    
    /// Запускает цикл обработки пакетов
    pub async fn run(&mut self) -> Result<()> {
        let mut buffer = [0u8; 65535]; // Максимальный размер UDP пакета
        
        loop {
            match self.socket.recv_from(&mut buffer).await {
                Ok((size, source)) => {
                    let data = &buffer[..size];
                    
                    // Обрабатываем пакет
                    match self.handler.handle_packet(source, data) {
                        Ok(Some(response)) => {
                            // Отправляем ответ если нужно
                            if let Err(e) = self.socket.send_to(&response, source).await {
                                eprintln!("[UDP] Failed to send response: {}", e);
                            }
                        }
                        Ok(None) => {
                            // Ответ не требуется
                        }
                        Err(e) => {
                            eprintln!("[UDP] Handler error: {}", e);
                        }
                    }
                }
                Err(e) => {
                    return Err(KScopeError::Io(e));
                }
            }
        }
    }
    
    /// Отправляет данные (для клиента)
    pub async fn send(&self, data: &[u8]) -> Result<usize> {
        self.socket.send(data).await
            .map_err(|e| KScopeError::Io(e))
    }
    
    /// Отправляет данные на конкретный адрес (для сервера)
    pub async fn send_to(&self, data: &[u8], addr: SocketAddr) -> Result<usize> {
        self.socket.send_to(data, addr).await
            .map_err(|e| KScopeError::Io(e))
    }
    
    /// Возвращает локальный адрес сокета
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.socket.local_addr()
            .map_err(|e| KScopeError::Io(e))
    }
}
