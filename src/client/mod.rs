use crate::tun::{TunDevice, TunConfig, TunPacket};
use crate::protocol::{ClientConfig, transport::TransportManager, handshake::HandshakeManager};
use crate::crypto::KeyPair;
use crate::Result;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::net::UdpSocket;
use std::net::SocketAddr;

pub struct KScopeClient {
    config: ClientConfig,
    tun_device: Option<Arc<Mutex<TunDevice>>>,
    transport_manager: Arc<Mutex<TransportManager>>,
    socket: Option<Arc<UdpSocket>>,
    session_id: Option<u32>,
}

impl KScopeClient {
    /// Создает новый VPN клиент
    pub async fn new(config: ClientConfig) -> Result<Self> {
        let session_id = Some(rand::random::<u32>());
        
        Ok(Self {
            config,
            tun_device: None,
            transport_manager: Arc::new(Mutex::new(TransportManager::new())),
            socket: None,
            session_id,
        })
    }
    
    /// Подключается к VPN серверу
    pub async fn connect(&mut self) -> Result<()> {
        println!("Connecting to {}...", self.config.client.server_addr);
        
        // 1. Создаем TUN устройство
        self.create_tun_interface().await?;
        
        // 2. Устанавливаем UDP соединение с сервером
        self.connect_to_server().await?;
        
        // 3. Выполняем handshake
        self.perform_handshake().await?;
        
        // 4. Запускаем основной цикл
        self.run().await?;
        
        Ok(())
    }
    
    /// Создает TUN интерфейс
    async fn create_tun_interface(&mut self) -> Result<()> {
        let tun_config = TunConfig {
            name: self.config.network.tun_name.clone(),
            address: self.config.network.tun_ip.clone(),
            mtu: self.config.network.mtu,
            persistent: false,
        };
        
        let tun_config_clone = tun_config.clone();
        
        println!("Creating TUN interface {}...", tun_config.name);
        let tun = TunDevice::create(tun_config)?;
        
        // Настраиваем маршруты
        if !self.config.network.routes.is_empty() {
            for route in &self.config.network.routes {
                if route == "0.0.0.0/0" || route == "default" {
                    crate::tun::route::add_default_route(&tun_config_clone.name, None)?;
                } else {
                    crate::tun::route::add_route(&tun_config_clone.name, route, None)?;
                }
            }
        }
        
        self.tun_device = Some(Arc::new(Mutex::new(tun)));
        Ok(())
    }
    
    /// Устанавливает UDP соединение с сервером
    async fn connect_to_server(&mut self) -> Result<()> {
        let server_addr: SocketAddr = self.config.client.server_addr.parse()
            .map_err(|e| crate::KScopeError::Config(format!("Invalid server address: {}", e)))?;
        
        let socket = UdpSocket::bind("0.0.0.0:0").await
            .map_err(|e| crate::KScopeError::Io(e))?;
        
        socket.connect(server_addr).await
            .map_err(|e| crate::KScopeError::Io(e))?;
        
        println!("Connected to server at {}", server_addr);
        self.socket = Some(Arc::new(socket));
        
        Ok(())
    }
    
    /// Выполняет криптографическое handshake
    async fn perform_handshake(&mut self) -> Result<()> {
        println!("Performing handshake...");
        
        // Загружаем ключи клиента
        let client_keys = KeyPair::load(&self.config.client.private_key)?;
        
        // Загружаем публичный ключ сервера
        let server_pubkey_str = std::fs::read_to_string(&self.config.client.server_public_key)
            .map_err(|e| crate::KScopeError::Io(e))?;
        let server_pubkey = crate::crypto::PublicKey::from_hex(server_pubkey_str.trim())?;
        
        // Создаем handshake init пакет
        let handshake_packet = HandshakeManager::create_init_packet(&client_keys, &server_pubkey)?;
        
        // Отправляем handshake init
        let socket = self.socket.as_ref().expect("Socket not initialized");
        let packet_data = handshake_packet.serialize(self.session_id.unwrap_or(0));
        socket.send(&packet_data).await
            .map_err(|e| crate::KScopeError::Io(e))?;
        
        println!("Handshake initiated");
        
        Ok(())
    }
    
    /// Основной цикл клиента
    async fn run(&mut self) -> Result<()> {
        println!("VPN client started. Press Ctrl+C to stop.");
        
        // Запускаем задачи
        let tun_reader = self.start_tun_reader();
        let network_reader = self.start_network_reader();
        
        // Игнорируем результаты, чтобы избежать предупреждений
        let _ = tokio::join!(tun_reader, network_reader);
        
        Ok(())
    }
    
    /// Запускает задачу чтения пакетов из TUN
    async fn start_tun_reader(&self) -> Result<()> {
        let tun_device = Arc::clone(self.tun_device.as_ref().expect("TUN device not initialized"));
        let socket = Arc::clone(self.socket.as_ref().expect("Socket not initialized"));
        
        let _ = tokio::spawn(async move {
            loop {
                let packet = {
                    let mut tun = tun_device.lock().await;
                    match tun.read() {
                        Ok(packet) => packet,
                        Err(e) => {
                            eprintln!("Error reading from TUN: {}", e);
                            break;
                        }
                    }
                };
                
                println!("Read packet from TUN: {} bytes", packet.data.len());
                
                if let Err(e) = socket.send(&packet.data).await {
                    eprintln!("Failed to send packet: {}", e);
                }
            }
            
            Ok::<(), crate::KScopeError>(())
        }).await;
        
        Ok(())
    }
    
    /// Запускает задачу чтения пакетов из сети
    async fn start_network_reader(&self) -> Result<()> {
        let socket = Arc::clone(self.socket.as_ref().expect("Socket not initialized"));
        let tun_device = Arc::clone(self.tun_device.as_ref().expect("TUN device not initialized"));
        
        let _ = tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            
            loop {
                match socket.recv(&mut buf).await {
                    Ok(n) => {
                        println!("Received packet from network: {} bytes", n);
                        
                        let packet = TunPacket::new(buf[..n].to_vec(), 0x0800);
                        
                        let mut tun = tun_device.lock().await;
                        if let Err(e) = tun.write(&packet) {
                            eprintln!("Failed to write to TUN: {}", e);
                        }
                    }
                    Err(e) => {
                        eprintln!("Error receiving from socket: {}", e);
                        break;
                    }
                }
            }
            
            Ok::<(), crate::KScopeError>(())
        }).await;
        
        Ok(())
    }
    
    /// Отключается от VPN
    pub async fn disconnect(&mut self) -> Result<()> {
        println!("Disconnecting...");
        
        if let Some(tun_arc) = self.tun_device.take() {
            // Закрываем TUN устройство
            if let Ok(tun_mutex) = Arc::try_unwrap(tun_arc) {
                let tun = tun_mutex.into_inner();
                tun.close()?;
            }
        }
        
        println!("Disconnected.");
        Ok(())
    }
}
