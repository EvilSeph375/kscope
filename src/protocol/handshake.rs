use crate::protocol::packet::{HandshakeInit, HandshakeResponse, Packet};

pub struct HandshakeManager;

impl HandshakeManager {
    pub fn create_init_packet(
        client_keys: &crate::crypto::KeyPair,
        _server_public_key: &crate::crypto::PublicKey,
    ) -> crate::Result<Packet> {
        use rand::RngCore;
        
        // Генерируем эфемерный ключ
        let mut ephemeral_public = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut ephemeral_public);
        
        // Создаем подпись (в реальности нужно подписывать хэш)
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let mut message = Vec::new();
        message.extend_from_slice(&ephemeral_public);
        message.extend_from_slice(&timestamp.to_be_bytes());
        
        let signature = client_keys.sign(&message);
        
        // Создаем nonce
        let mut nonce_bytes = [0u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = u64::from_be_bytes(nonce_bytes);
        
        let handshake_init = HandshakeInit {
            ephemeral_public,
            signature,
            timestamp,
            nonce,
        };
        
        Ok(Packet::HandshakeInit(handshake_init))
    }
    
    pub fn process_init_packet(
        packet: &HandshakeInit,
        _server_keys: &crate::crypto::KeyPair,
    ) -> crate::Result<Packet> {
        use rand::RngCore;
        
        // Валидация пакета
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        // Проверяем timestamp (допустимое отклонение ±60 секунд)
        if packet.timestamp.abs_diff(current_time) > 60 {
            return Err(crate::KScopeError::Protocol(
                "Invalid timestamp".to_string()
            ));
        }
        
        // Генерируем ответ
        let mut ephemeral_public = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut ephemeral_public);
        
        // Заглушки для зашифрованных данных (в реальности нужно шифровать)
        let mut encrypted_static = [0u8; 48];
        rand::rngs::OsRng.fill_bytes(&mut encrypted_static);
        
        let mut encrypted_keys = [0u8; 64];
        rand::rngs::OsRng.fill_bytes(&mut encrypted_keys);
        
        let handshake_response = HandshakeResponse {
            ephemeral_public,
            encrypted_static,
            encrypted_keys,
        };
        
        Ok(Packet::HandshakeResponse(handshake_response))
    }
}
