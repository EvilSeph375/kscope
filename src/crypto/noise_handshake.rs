// src/crypto/noise_handshake.rs
use crate::crypto::{KeyPair, PublicKey, Result, CryptoError};
use snow::{Builder, TransportState};
use std::sync::{Arc, Mutex};

// Переименовываем импорт, чтобы избежать конфликта имен
use snow::HandshakeState as SnowHandshakeState;

/// Состояние Noise handshake в нашем приложении
pub enum HandshakePhase {
    /// Начальное состояние (ждут инициацию)
    Init,
    /// Отправлено init сообщение
    SentInit,
    /// Получен ответ
    ReceivedResponse,
    /// Handshake завершен
    Completed(TransportState),
    /// Ошибка
    Error(String),
}

/// Результат handshake
pub struct HandshakeResult {
    pub transport: TransportState,
    pub handshake_hash: [u8; 32],
    pub local_static_public: [u8; 32],
    pub remote_static_public: [u8; 32],
}

/// Менеджер Noise handshake
pub struct NoiseHandshake {
    state: Arc<Mutex<HandshakePhase>>,
    pattern: String,
    local_keypair: KeyPair,
    remote_public_key: Option<PublicKey>,
}

// Вспомогательная функция для преобразования ошибок snow в CryptoError
fn snow_error_to_crypto_error(err: snow::Error) -> CryptoError {
    CryptoError::Generic(format!("Snow error: {}", err))
}

impl NoiseHandshake {
    /// Создает инициатор (клиент)
    pub fn initiator(local_keypair: KeyPair, remote_public_key: PublicKey) -> Result<Self> {
        Ok(Self {
            state: Arc::new(Mutex::new(HandshakePhase::Init)),
            pattern: "Noise_IK_25519_ChaChaPoly_BLAKE2s".to_string(),
            local_keypair,
            remote_public_key: Some(remote_public_key),
        })
    }
    
    /// Создает респондер (сервер)
    pub fn responder(local_keypair: KeyPair) -> Result<Self> {
        Ok(Self {
            state: Arc::new(Mutex::new(HandshakePhase::Init)),
            pattern: "Noise_IK_25519_ChaChaPoly_BLAKE2s".to_string(),
            local_keypair,
            remote_public_key: None,
        })
    }
    
    /// Генерирует init сообщение (для клиента)
    pub fn write_init_message(&mut self) -> Result<Vec<u8>> {
        // Парсим паттерн с обработкой ошибки snow
        let builder_result: std::result::Result<Builder, snow::Error> = 
            Builder::new(self.pattern.parse());
        let mut builder = builder_result.map_err(snow_error_to_crypto_error)?;
        
        // Получаем байты ключей
        let local_private_bytes = self.local_keypair.private_key_bytes();
        let remote_public_bytes = self.remote_public_key
            .as_ref()
            .ok_or_else(|| CryptoError::Generic("No remote public key".to_string()))?
            .to_bytes();
        
        // Настраиваем ключи
        builder = builder
            .local_private_key(&local_private_bytes)
            .remote_public_key(&remote_public_bytes);
        
        let mut handshake_state = builder.build_initiator()
            .map_err(snow_error_to_crypto_error)?;
        
        // Генерируем init сообщение
        let mut message = vec![0u8; 1024];
        let len = handshake_state.write_message(&[], &mut message)
            .map_err(snow_error_to_crypto_error)?;
        message.truncate(len);
        
        // Обновляем состояние
        *self.state.lock().unwrap() = HandshakePhase::SentInit;
        
        Ok(message)
    }
    
    /// Обрабатывает входящее сообщение (для сервера)
    pub fn read_message(&mut self, message: &[u8]) -> Result<Option<Vec<u8>>> {
        // Парсим паттерн
        let builder_result: std::result::Result<Builder, snow::Error> = 
            Builder::new(self.pattern.parse());
        let mut builder = builder_result.map_err(snow_error_to_crypto_error)?;
        
        // Для респондера нужен только локальный ключ
        let local_private_bytes = self.local_keypair.private_key_bytes();
        builder = builder.local_private_key(&local_private_bytes);
        
        let mut handshake_state = builder.build_responder()
            .map_err(snow_error_to_crypto_error)?;
        
        // Читаем входящее сообщение
        let mut response = vec![0u8; 1024];
        let len = handshake_state.read_message(message, &mut response)
            .map_err(snow_error_to_crypto_error)?;
        
        if len > 0 {
            response.truncate(len);
            
            // Если нужно отправить ответ
            if handshake_state.is_handshake_finished() {
                let transport = handshake_state.into_transport_mode()
                    .map_err(snow_error_to_crypto_error)?;
                *self.state.lock().unwrap() = HandshakePhase::Completed(transport);
                Ok(Some(response))
            } else {
                *self.state.lock().unwrap() = HandshakePhase::ReceivedResponse;
                Ok(Some(response))
            }
        } else {
            Ok(None)
        }
    }
    
    /// Завершает handshake (для клиента после получения ответа)
    pub fn finish_handshake(&mut self, _response: &[u8]) -> Result<HandshakeResult> {
        // TODO: Реализовать завершение handshake
        Err(CryptoError::Generic("Not implemented yet".to_string()))
    }
    
    /// Проверяет, завершен ли handshake
    pub fn is_completed(&self) -> bool {
        matches!(*self.state.lock().unwrap(), HandshakePhase::Completed(_))
    }
    
    /// Возвращает текущую фазу handshake
    pub fn phase(&self) -> HandshakePhase {
        let state = self.state.lock().unwrap();
        match &*state {
            HandshakePhase::Init => HandshakePhase::Init,
            HandshakePhase::SentInit => HandshakePhase::SentInit,
            HandshakePhase::ReceivedResponse => HandshakePhase::ReceivedResponse,
            HandshakePhase::Completed(ref transport) => {
                // Клонирование TransportState может быть сложным, 
                // возвращаем Completed без транспорта для простоты
                HandshakePhase::Error("Cannot clone transport".to_string())
            }
            HandshakePhase::Error(ref msg) => HandshakePhase::Error(msg.clone()),
        }
    }
}
