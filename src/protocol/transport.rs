use crate::crypto::SessionKeys;
use crate::protocol::packet::{Packet, TransportData};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Debug, Clone)]
pub struct TransportSession {
    session_id: u32,
    keys: Arc<Mutex<SessionKeys>>,
    send_sequence: u64,
    recv_sequence: u64,
}

impl TransportSession {
    pub fn new(session_id: u32, keys: SessionKeys) -> Self {
        Self {
            session_id,
            keys: Arc::new(Mutex::new(keys)),
            send_sequence: 0,
            recv_sequence: 0,
        }
    }
    
    pub fn session_id(&self) -> u32 {
        self.session_id
    }
    
    pub async fn encrypt_packet(&mut self, plaintext: &[u8]) -> crate::Result<Bytes> {
        let mut keys = self.keys.lock().await;
        
        // Добавляем заголовок последовательности
        let mut data = BytesMut::with_capacity(8 + plaintext.len());
        data.put_u64(self.send_sequence);
        data.put_slice(plaintext);
        
        // Шифруем
        let ciphertext = keys.encrypt(&data, &[])?;
        
        // Создаем транспортный пакет
        let transport_data = TransportData::new(keys.send_nonce - 1, Bytes::from(ciphertext));
        let packet = Packet::TransportData(transport_data);
        
        self.send_sequence += 1;
        
        Ok(packet.serialize(self.session_id))
    }
    
    pub async fn decrypt_packet(&mut self, ciphertext: &[u8]) -> crate::Result<Bytes> {
        let mut keys = self.keys.lock().await;
        
        // Дешифруем
        let plaintext = keys.decrypt(ciphertext, &[])?;
        
        // Извлекаем заголовок последовательности
        let mut buf = Bytes::copy_from_slice(&plaintext);
        if buf.len() < 8 {
            return Err(crate::KScopeError::Protocol(
                "Decrypted packet too small".to_string()
            ));
        }
        
        let sequence = buf.get_u64();
        
        // Проверяем последовательность (защита от replay атак)
        if sequence < self.recv_sequence {
            return Err(crate::KScopeError::Protocol(
                format!("Invalid sequence: {} < {}", sequence, self.recv_sequence)
            ));
        }
        
        self.recv_sequence = sequence + 1;
        
        Ok(buf.copy_to_bytes(buf.remaining()))
    }
}

// Менеджер транспортных сессий
pub struct TransportManager {
    sessions: std::collections::HashMap<u32, TransportSession>,
}

impl TransportManager {
    pub fn new() -> Self {
        Self {
            sessions: std::collections::HashMap::new(),
        }
    }
    
    pub fn add_session(&mut self, session_id: u32, keys: SessionKeys) {
        let session = TransportSession::new(session_id, keys);
        self.sessions.insert(session_id, session);
    }
    
    pub fn remove_session(&mut self, session_id: u32) -> Option<TransportSession> {
        self.sessions.remove(&session_id)
    }
    
    pub fn get_session(&self, session_id: u32) -> Option<&TransportSession> {
        self.sessions.get(&session_id)
    }
    
    pub fn get_session_mut(&mut self, session_id: u32) -> Option<&mut TransportSession> {
        self.sessions.get_mut(&session_id)
    }
}
