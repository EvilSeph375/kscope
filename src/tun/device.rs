use crate::KScopeError;
use super::{TunConfig, TunPacket};
use std::net::Ipv4Addr;
use std::process::Command;

/// TUN устройство для захвата и отправки IP-пакетов
pub struct TunDevice {
    iface: tun_tap::Iface,
    config: TunConfig,
    mtu: usize,
}

impl TunDevice {
    /// Создает новое TUN устройство
    pub fn create(config: TunConfig) -> Result<Self, KScopeError> {
        // Создаем TUN интерфейс
        let iface = tun_tap::Iface::without_packet_info(
            &config.name,
            tun_tap::Mode::Tun,
        ).map_err(|e| KScopeError::Io(e))?;
        
        let device = Self {
            iface,
            config: config.clone(),
            mtu: config.mtu as usize,
        };
        
        // Настраиваем интерфейс
        device.configure_interface()?;
        
        Ok(device)
    }
    
    /// Настраивает сетевой интерфейс (IP, маршруты и т.д.)
    fn configure_interface(&self) -> Result<(), KScopeError> {
        let (ip_addr, prefix_len) = parse_cidr(&self.config.address)?;
        
        // Устанавливаем IP адрес
        if let Err(e) = Command::new("ip")
            .args(["addr", "add", &self.config.address, "dev", &self.config.name])
            .output()
        {
            log::warn!("Failed to set IP address (might need sudo): {}", e);
        }
        
        // Включаем интерфейс
        if let Err(e) = Command::new("ip")
            .args(["link", "set", "up", "dev", &self.config.name])
            .output()
        {
            log::warn!("Failed to bring interface up: {}", e);
        }
        
        // Устанавливаем MTU
        if let Err(e) = Command::new("ip")
            .args(["link", "set", "mtu", &self.config.mtu.to_string(), "dev", &self.config.name])
            .output()
        {
            log::warn!("Failed to set MTU: {}", e);
        }
        
        println!(
            "TUN interface {} created: {}/{} (MTU: {})",
            self.config.name, ip_addr, prefix_len, self.config.mtu
        );
        
        Ok(())
    }
    
    /// Читает пакет из TUN устройства (блокирующая операция)
    pub fn read(&mut self) -> Result<TunPacket, KScopeError> {
        let mut buf = vec![0u8; self.mtu + 4]; // +4 для заголовка TUN
        
        match self.iface.recv(&mut buf) {
            Ok(n) => {
                if n < 4 {
                    return Err(KScopeError::Io(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "Packet too small",
                    )));
                }
                
                // Извлекаем protocol из заголовка TUN (2 байта, big-endian)
                let protocol = u16::from_be_bytes([buf[2], buf[3]]);
                
                // Данные начинаются с 4-го байта
                let data = buf[4..n].to_vec();
                
                Ok(TunPacket::new(data, protocol))
            }
            Err(e) => Err(KScopeError::Io(e)),
        }
    }
    
    /// Неблокирующее чтение с таймаутом
    pub fn read_timeout(&mut self, timeout_ms: u64) -> Result<Option<TunPacket>, KScopeError> {
        use std::io::ErrorKind;
        use std::time::{Duration, Instant};
        
        // Настраиваем неблокирующий режим (если поддерживается)
        // Для простоты сделаем просто цикл с небольшими паузами
        
        let start = Instant::now();
        let timeout = Duration::from_millis(timeout_ms);
        
        while start.elapsed() < timeout {
            match self.read() {
                Ok(packet) => return Ok(Some(packet)),
                Err(e) => {
                    // Если это был бы таймаут в неблокирующем режиме, продолжаем
                    if let KScopeError::Io(io_err) = &e {
                        if io_err.kind() == ErrorKind::WouldBlock {
                            std::thread::sleep(Duration::from_millis(10));
                            continue;
                        }
                    }
                    return Err(e);
                }
            }
        }
        
        Ok(None) // Таймаут
    }
    
    /// Записывает пакет в TUN устройство
    pub fn write(&mut self, packet: &TunPacket) -> Result<(), KScopeError> {
        // Создаем буфер с TUN заголовком
        let mut buf = Vec::with_capacity(packet.data.len() + 4);
        
        // Флаги TUN (2 байта) - обычно 0
        buf.extend_from_slice(&[0x00, 0x00]);
        
        // Protocol (2 байта, big-endian)
        buf.extend_from_slice(&packet.protocol.to_be_bytes());
        
        // Данные пакета
        buf.extend_from_slice(&packet.data);
        
        // Отправляем пакет
        self.iface.send(&buf)
            .map_err(|e| KScopeError::Io(e))?;
        
        Ok(())
    }
    
    /// Возвращает имя интерфейса
    pub fn name(&self) -> &str {
        &self.config.name
    }
    
    /// Возвращает MTU
    pub fn mtu(&self) -> u16 {
        self.config.mtu
    }
    
    /// Возвращает IP адрес интерфейса
    pub fn ip_address(&self) -> Result<Ipv4Addr, KScopeError> {
        let (ip_addr, _) = parse_cidr(&self.config.address)?;
        Ok(ip_addr)
    }
    
    /// Закрывает TUN устройство
    pub fn close(self) -> Result<(), KScopeError> {
        // При удалении Iface дескриптор автоматически закрывается
        // Но можно явно удалить интерфейс
        if !self.config.persistent {
            let _ = Command::new("ip")
                .args(["link", "delete", "dev", &self.config.name])
                .output();
        }
        
        Ok(())
    }
}

/// Парсит CIDR нотацию (например, "10.0.0.1/24")
fn parse_cidr(cidr: &str) -> Result<(Ipv4Addr, u8), KScopeError> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return Err(KScopeError::Config(
            format!("Invalid CIDR notation: {}", cidr)
        ));
    }
    
    let ip_addr: Ipv4Addr = parts[0].parse()
        .map_err(|e| KScopeError::Config(
            format!("Invalid IP address: {}", e)
        ))?;
    
    let prefix_len: u8 = parts[1].parse()
        .map_err(|e| KScopeError::Config(
            format!("Invalid prefix length: {}", e)
        ))?;
    
    if prefix_len > 32 {
        return Err(KScopeError::Config(
            format!("Invalid prefix length: {}", prefix_len)
        ));
    }
    
    Ok((ip_addr, prefix_len))
}

/// Вспомогательные функции для работы с IP пакетами
pub mod ip_utils {
    use std::net::Ipv6Addr;
    
    /// Извлекает протокол из IP пакета
    pub fn get_ip_protocol(packet: &[u8]) -> Option<u8> {
        if packet.len() < 1 {
            return None;
        }
        
        let version = packet[0] >> 4;
        match version {
            4 => {
                // IPv4
                if packet.len() >= 9 {
                    Some(packet[9])  // Protocol field in IPv4 header
                } else {
                    None
                }
            }
            6 => {
                // IPv6 - next header is at byte 6
                if packet.len() >= 7 {
                    Some(packet[6])
                } else {
                    None
                }
            }
            _ => None,
        }
    }
    
    /// Проверяет, является ли пакет IPv4
    pub fn is_ipv4(packet: &[u8]) -> bool {
        packet.len() >= 1 && (packet[0] >> 4) == 4
    }
    
    /// Проверяет, является ли пакет IPv6
    pub fn is_ipv6(packet: &[u8]) -> bool {
        packet.len() >= 1 && (packet[0] >> 4) == 6
    }
    
    /// Извлекает исходный IP адрес из пакета
    pub fn get_source_ip(packet: &[u8]) -> Option<String> {
        if is_ipv4(packet) && packet.len() >= 20 {
            let src = &packet[12..16];
            Some(format!("{}.{}.{}.{}", src[0], src[1], src[2], src[3]))
        } else if is_ipv6(packet) && packet.len() >= 40 {
            let src = &packet[8..24];
            let addr = Ipv6Addr::from([
                src[0], src[1], src[2], src[3],
                src[4], src[5], src[6], src[7],
                src[8], src[9], src[10], src[11],
                src[12], src[13], src[14], src[15],
            ]);
            Some(addr.to_string())
        } else {
            None
        }
    }
    
    /// Извлекает IP адрес назначения из пакета
    pub fn get_destination_ip(packet: &[u8]) -> Option<String> {
        if is_ipv4(packet) && packet.len() >= 20 {
            let dst = &packet[16..20];
            Some(format!("{}.{}.{}.{}", dst[0], dst[1], dst[2], dst[3]))
        } else if is_ipv6(packet) && packet.len() >= 40 {
            let dst = &packet[24..40];
            let addr = Ipv6Addr::from([
                dst[0], dst[1], dst[2], dst[3],
                dst[4], dst[5], dst[6], dst[7],
                dst[8], dst[9], dst[10], dst[11],
                dst[12], dst[13], dst[14], dst[15],
            ]);
            Some(addr.to_string())
        } else {
            None
        }
    }
}

/// Утилиты для работы с маршрутами
pub mod route {
    use std::process::Command;
    use crate::KScopeError;
    
    /// Добавляет маршрут через TUN интерфейс
    pub fn add_route(interface: &str, destination: &str, via: Option<&str>) -> Result<(), KScopeError> {
        let mut cmd = Command::new("ip");
        cmd.args(["route", "add", destination, "dev", interface]);
        
        if let Some(gateway) = via {
            cmd.arg("via").arg(gateway);
        }
        
        cmd.output()
            .map_err(|e| KScopeError::Io(e))?;
        
        Ok(())
    }
    
    /// Удаляет маршрут
    pub fn delete_route(interface: &str, destination: &str) -> Result<(), KScopeError> {
        Command::new("ip")
            .args(["route", "delete", destination, "dev", interface])
            .output()
            .map_err(|e| KScopeError::Io(e))?;
        
        Ok(())
    }
    
    /// Добавляет маршрут по умолчанию через TUN интерфейс
    pub fn add_default_route(interface: &str, via: Option<&str>) -> Result<(), KScopeError> {
        add_route(interface, "default", via)
    }
}
