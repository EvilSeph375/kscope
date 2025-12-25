use crate::tun::{TunDevice, TunConfig};
use crate::protocol::{ClientConfig, transport::TransportManager, handshake::HandshakeManager};
use crate::crypto::KeyPair;
use crate::{Result, KScopeError};
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

        // TODO: Пока пропускаем остальное для теста TUN
        println!("✅ TUN interface created successfully!");
        println!("[TEST MODE] Skipping server connection for now");
        
        // Просто держим программу запущенной
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }
    }
    
    async fn create_tun_interface(&mut self) -> Result<()> {
        // Парсим CIDR нотацию
        let (ip_str, prefix_len) = parse_cidr(&self.config.network.tun_ip)?;
        let ip = ip_str.parse::<std::net::Ipv4Addr>()
            .map_err(|e| KScopeError::Config(format!("Invalid IP address: {}", e)))?;

        let tun_config = TunConfig {
            name: self.config.network.tun_name.clone(),
            ip,
            prefix_len,
            mtu: self.config.network.mtu,
        };

        println!("Creating TUN interface {}...", tun_config.name);
        
        // Клонируем конфиг перед передачей в create
        let tun_config_clone = tun_config.clone();
        let tun = TunDevice::create(tun_config)?;
        
        // Настраиваем маршруты (заглушки)
        if !self.config.network.routes.is_empty() {
            println!("[MOCK] Configuring routes...");
            for route in &self.config.network.routes {
                if route == "0.0.0.0/0" || route == "default" {
                    println!("  Would add default route via {}", tun_config_clone.name);
                } else {
                    println!("  Would add route {} via {}", route, tun_config_clone.name);
                }
            }
        }

        self.tun_device = Some(Arc::new(Mutex::new(tun)));
        Ok(())
    }
    
    pub async fn disconnect(&mut self) -> Result<()> {
        println!("Disconnecting...");
        
        // Закрываем TUN устройство
        if let Some(tun_arc) = self.tun_device.take() {
            match Arc::try_unwrap(tun_arc) {
                Ok(tun_mutex) => {
                    let tun = tun_mutex.into_inner();
                    tun.close()?;
                }
                Err(_) => {
                    println!("TUN device is still in use by other references");
                }
            }
        }

        println!("Disconnected.");
        Ok(())
    }
}

/// Парсит CIDR нотацию (например, "10.0.0.2/24")
fn parse_cidr(cidr: &str) -> std::result::Result<(&str, u8), KScopeError> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return Err(KScopeError::Config(
            format!("Invalid CIDR notation: {}", cidr)
        ));
    }

    let ip_str = parts[0];
    let prefix_len: u8 = parts[1].parse()
        .map_err(|e| KScopeError::Config(format!("Invalid prefix length: {}", e)))?;

    if prefix_len > 32 {
        return Err(KScopeError::Config(
            format!("Invalid prefix length: {}", prefix_len)
        ));
    }

    Ok((ip_str, prefix_len))
}
