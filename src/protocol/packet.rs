use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::convert::TryInto;

// Типы пакетов
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    HandshakeInit = 0x01,     // Инициализация рукопожатия
    HandshakeResponse = 0x02, // Ответ рукопожатия
    TransportData = 0x03,     // Данные туннеля
    KeepAlive = 0x04,         // Keep-alive
    ErrorPacket = 0xFF,       // Ошибка (переименовываем, чтобы не было конфликта)
}

impl TryFrom<u8> for PacketType {
    type Error = String;
    
    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0x01 => Ok(PacketType::HandshakeInit),
            0x02 => Ok(PacketType::HandshakeResponse),
            0x03 => Ok(PacketType::TransportData),
            0x04 => Ok(PacketType::KeepAlive),
            0xFF => Ok(PacketType::ErrorPacket),
            _ => Err(format!("Invalid packet type: {}", value)),
        }
    }
}

// Базовый заголовок пакета (8 байт)
#[derive(Debug, Clone)]
pub struct PacketHeader {
    pub version: u8,          // Версия протокола (0x01)
    pub packet_type: PacketType,
    pub data_len: u16,        // Длина данных (без заголовка)
    pub session_id: u32,      // Идентификатор сессии
}

impl PacketHeader {
    pub const SIZE: usize = 8;
    
    pub fn new(packet_type: PacketType, data_len: u16, session_id: u32) -> Self {
        Self {
            version: 0x01,
            packet_type,
            data_len,
            session_id,
        }
    }
    
    pub fn serialize(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[0] = self.version;
        buf[1] = self.packet_type as u8;
        buf[2..4].copy_from_slice(&self.data_len.to_be_bytes());
        buf[4..8].copy_from_slice(&self.session_id.to_be_bytes());
        buf
    }
    
    pub fn deserialize(data: &[u8]) -> crate::Result<Self> {
        if data.len() < Self::SIZE {
            return Err(crate::KScopeError::Protocol(
                format!("Packet too small: {} bytes", data.len())
            ));
        }
        
        let version = data[0];
        if version != 0x01 {
            return Err(crate::KScopeError::Protocol(
                format!("Unsupported protocol version: {}", version)
            ));
        }
        
        let packet_type = PacketType::try_from(data[1])
            .map_err(|e| crate::KScopeError::Protocol(e))?;
        
        let data_len = u16::from_be_bytes([data[2], data[3]]);
        let session_id = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        
        Ok(Self {
            version,
            packet_type,
            data_len,
            session_id,
        })
    }
}

// Пакет инициализации рукопожатия
#[derive(Debug, Clone)]
pub struct HandshakeInit {
    pub ephemeral_public: [u8; 32],    // Эфемерный публичный ключ клиента
    pub signature: [u8; 64],           // Подпись статического ключа клиента
    pub timestamp: u64,                // Метка времени
    pub nonce: u64,                    // Случайное число
}

impl HandshakeInit {
    pub const SIZE: usize = 32 + 64 + 8 + 8; // 112 байт
    
    pub fn serialize(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[0..32].copy_from_slice(&self.ephemeral_public);
        buf[32..96].copy_from_slice(&self.signature);
        buf[96..104].copy_from_slice(&self.timestamp.to_be_bytes());
        buf[104..112].copy_from_slice(&self.nonce.to_be_bytes());
        buf
    }
    
    pub fn deserialize(data: &[u8]) -> crate::Result<Self> {
        if data.len() != Self::SIZE {
            return Err(crate::KScopeError::Protocol(
                format!("Invalid handshake init size: {} bytes", data.len())
            ));
        }
        
        let mut ephemeral_public = [0u8; 32];
        ephemeral_public.copy_from_slice(&data[0..32]);
        
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&data[32..96]);
        
        let timestamp = u64::from_be_bytes(data[96..104].try_into().unwrap());
        let nonce = u64::from_be_bytes(data[104..112].try_into().unwrap());
        
        Ok(Self {
            ephemeral_public,
            signature,
            timestamp,
            nonce,
        })
    }
}

// Пакет ответа рукопожатия
#[derive(Debug, Clone)]
pub struct HandshakeResponse {
    pub ephemeral_public: [u8; 32],    // Эфемерный публичный ключ сервера
    pub encrypted_static: [u8; 48],    // Зашифрованный статический ключ сервера
    pub encrypted_keys: [u8; 64],      // Зашифрованные ключи сессии
}

impl HandshakeResponse {
    pub const SIZE: usize = 32 + 48 + 64; // 144 байт
    
    pub fn serialize(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[0..32].copy_from_slice(&self.ephemeral_public);
        buf[32..80].copy_from_slice(&self.encrypted_static);
        buf[80..144].copy_from_slice(&self.encrypted_keys);
        buf
    }
    
    pub fn deserialize(data: &[u8]) -> crate::Result<Self> {
        if data.len() != Self::SIZE {
            return Err(crate::KScopeError::Protocol(
                format!("Invalid handshake response size: {} bytes", data.len())
            ));
        }
        
        let mut ephemeral_public = [0u8; 32];
        ephemeral_public.copy_from_slice(&data[0..32]);
        
        let mut encrypted_static = [0u8; 48];
        encrypted_static.copy_from_slice(&data[32..80]);
        
        let mut encrypted_keys = [0u8; 64];
        encrypted_keys.copy_from_slice(&data[80..144]);
        
        Ok(Self {
            ephemeral_public,
            encrypted_static,
            encrypted_keys,
        })
    }
}

// Пакет транспортных данных
#[derive(Debug, Clone)]
pub struct TransportData {
    pub nonce: u64,            // Nonce для шифрования
    pub ciphertext: Bytes,     // Зашифрованные данные + тег Poly1305
}

impl TransportData {
    pub fn new(nonce: u64, ciphertext: Bytes) -> Self {
        Self { nonce, ciphertext }
    }
    
    pub fn serialize(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(8 + self.ciphertext.len());
        buf.put_u64(self.nonce);
        buf.put_slice(&self.ciphertext);
        buf.freeze()
    }
    
    pub fn deserialize(mut data: Bytes) -> crate::Result<Self> {
        if data.len() < 8 {
            return Err(crate::KScopeError::Protocol(
                "Transport data too small".to_string()
            ));
        }
        
        let nonce = data.get_u64();
        let ciphertext = data.copy_to_bytes(data.remaining());
        
        Ok(Self { nonce, ciphertext })
    }
}

// Keep-alive пакет
#[derive(Debug, Clone)]
pub struct KeepAlive {
    pub timestamp: u64,
    pub random_data: [u8; 16],
}

impl KeepAlive {
    pub const SIZE: usize = 8 + 16; // 24 байта
    
    pub fn new() -> Self {
        use rand::RngCore;
        
        let mut random_data = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut random_data);
        
        Self {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            random_data,
        }
    }
    
    pub fn serialize(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[0..8].copy_from_slice(&self.timestamp.to_be_bytes());
        buf[8..24].copy_from_slice(&self.random_data);
        buf
    }
    
    pub fn deserialize(data: &[u8]) -> crate::Result<Self> {
        if data.len() != Self::SIZE {
            return Err(crate::KScopeError::Protocol(
                format!("Invalid keepalive size: {} bytes", data.len())
            ));
        }
        
        let timestamp = u64::from_be_bytes(data[0..8].try_into().unwrap());
        let mut random_data = [0u8; 16];
        random_data.copy_from_slice(&data[8..24]);
        
        Ok(Self {
            timestamp,
            random_data,
        })
    }
}

// Пакет ошибки
#[derive(Debug, Clone)]
pub struct ErrorPacket {
    pub code: u16,
    pub message: String,
}

impl ErrorPacket {
    pub fn new(code: u16, message: &str) -> Self {
        Self {
            code,
            message: message.to_string(),
        }
    }
    
    pub fn serialize(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(2 + self.message.len());
        buf.put_u16(self.code);
        buf.put_slice(self.message.as_bytes());
        buf.freeze()
    }
    
    pub fn deserialize(mut data: Bytes) -> crate::Result<Self> {
        if data.len() < 2 {
            return Err(crate::KScopeError::Protocol(
                "Error packet too small".to_string()
            ));
        }
        
        let code = data.get_u16();
        let message_bytes = data.copy_to_bytes(data.remaining());
        let message = String::from_utf8_lossy(&message_bytes).to_string();
        
        Ok(Self { code, message })
    }
}

// Объединенный пакет
#[derive(Debug, Clone)]
pub enum Packet {
    HandshakeInit(HandshakeInit),
    HandshakeResponse(HandshakeResponse),
    TransportData(TransportData),
    KeepAlive(KeepAlive),
    Error(ErrorPacket),
}

impl Packet {
    pub fn packet_type(&self) -> PacketType {
        match self {
            Packet::HandshakeInit(_) => PacketType::HandshakeInit,
            Packet::HandshakeResponse(_) => PacketType::HandshakeResponse,
            Packet::TransportData(_) => PacketType::TransportData,
            Packet::KeepAlive(_) => PacketType::KeepAlive,
            Packet::Error(_) => PacketType::ErrorPacket,
        }
    }
    
    pub fn serialize(&self, session_id: u32) -> Bytes {
        match self {
            Packet::HandshakeInit(pkt) => {
                let data = pkt.serialize();
                let header = PacketHeader::new(
                    PacketType::HandshakeInit,
                    data.len() as u16,
                    session_id,
                );
                let mut buf = BytesMut::with_capacity(PacketHeader::SIZE + data.len());
                buf.put_slice(&header.serialize());
                buf.put_slice(&data);
                buf.freeze()
            }
            Packet::HandshakeResponse(pkt) => {
                let data = pkt.serialize();
                let header = PacketHeader::new(
                    PacketType::HandshakeResponse,
                    data.len() as u16,
                    session_id,
                );
                let mut buf = BytesMut::with_capacity(PacketHeader::SIZE + data.len());
                buf.put_slice(&header.serialize());
                buf.put_slice(&data);
                buf.freeze()
            }
            Packet::TransportData(pkt) => {
                let data = pkt.serialize();
                let header = PacketHeader::new(
                    PacketType::TransportData,
                    data.len() as u16,
                    session_id,
                );
                let mut buf = BytesMut::with_capacity(PacketHeader::SIZE + data.len());
                buf.put_slice(&header.serialize());
                buf.put_slice(&data);
                buf.freeze()
            }
            Packet::KeepAlive(pkt) => {
                let data = pkt.serialize();
                let header = PacketHeader::new(
                    PacketType::KeepAlive,
                    data.len() as u16,
                    session_id,
                );
                let mut buf = BytesMut::with_capacity(PacketHeader::SIZE + data.len());
                buf.put_slice(&header.serialize());
                buf.put_slice(&data);
                buf.freeze()
            }
            Packet::Error(pkt) => {
                let data = pkt.serialize();
                let header = PacketHeader::new(
                    PacketType::ErrorPacket,
                    data.len() as u16,
                    session_id,
                );
                let mut buf = BytesMut::with_capacity(PacketHeader::SIZE + data.len());
                buf.put_slice(&header.serialize());
                buf.put_slice(&data);
                buf.freeze()
            }
        }
    }
    
    pub fn deserialize(data: &[u8]) -> crate::Result<(Packet, u32)> {
        if data.len() < PacketHeader::SIZE {
            return Err(crate::KScopeError::Protocol(
                "Packet too small".to_string()
            ));
        }
        
        let header = PacketHeader::deserialize(&data[0..PacketHeader::SIZE])?;
        let packet_data = &data[PacketHeader::SIZE..PacketHeader::SIZE + header.data_len as usize];
        
        let packet = match header.packet_type {
            PacketType::HandshakeInit => {
                let pkt = HandshakeInit::deserialize(packet_data)?;
                Packet::HandshakeInit(pkt)
            }
            PacketType::HandshakeResponse => {
                let pkt = HandshakeResponse::deserialize(packet_data)?;
                Packet::HandshakeResponse(pkt)
            }
            PacketType::TransportData => {
                let pkt = TransportData::deserialize(Bytes::copy_from_slice(packet_data))?;
                Packet::TransportData(pkt)
            }
            PacketType::KeepAlive => {
                let pkt = KeepAlive::deserialize(packet_data)?;
                Packet::KeepAlive(pkt)
            }
            PacketType::ErrorPacket => {
                let pkt = ErrorPacket::deserialize(Bytes::copy_from_slice(packet_data))?;
                Packet::Error(pkt)
            }
        };
        
        Ok((packet, header.session_id))
    }
}
