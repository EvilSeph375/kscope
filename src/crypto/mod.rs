pub mod noise;
pub mod keys;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("Signature verification failed")]
    SignatureFailed,
    #[error("Key generation failed")]
    KeyGenerationFailed,
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("Generic error: {0}")]
    Generic(String),
}

pub type Result<T> = std::result::Result<T, CryptoError>;

// Re-export commonly used types
pub use keys::{KeyPair, PublicKey, PrivateKey, SharedSecret, LegacyKeyPair};
pub use noise::{NoiseHandshake, HandshakeState, HandshakeResult, SessionKeys};

// AEAD encryption/decryption
pub fn encrypt(key: &[u8; 32], nonce: u64, plaintext: &[u8], _additional_data: &[u8]) -> Result<Vec<u8>> {
    use chacha20poly1305::{aead::{Aead, KeyInit}, ChaCha20Poly1305, Nonce};
    
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
    
    // Convert 64-bit nonce to 96-bit for ChaCha20-Poly1305
    let mut full_nonce = [0u8; 12];
    full_nonce[4..].copy_from_slice(&nonce.to_le_bytes());
    
    let nonce = Nonce::from_slice(&full_nonce);
    
    cipher.encrypt(nonce, plaintext)
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))
}

pub fn decrypt(key: &[u8; 32], nonce: u64, ciphertext: &[u8], _additional_data: &[u8]) -> Result<Vec<u8>> {
    use chacha20poly1305::{aead::{Aead, KeyInit}, ChaCha20Poly1305, Nonce};
    
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;
    
    let mut full_nonce = [0u8; 12];
    full_nonce[4..].copy_from_slice(&nonce.to_le_bytes());
    
    let nonce = Nonce::from_slice(&full_nonce);
    
    cipher.decrypt(nonce, ciphertext)
        .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))
}

// Hash function (BLAKE3)
pub fn blake3_hash(data: &[u8]) -> [u8; 32] {
    blake3::hash(data).into()
}

pub fn hkdf(chaining_key: &[u8; 32], input_key_material: &[u8], num_outputs: usize) -> Vec<[u8; 32]> {
    use blake3::Hasher;
    
    let mut outputs: Vec<[u8; 32]> = Vec::with_capacity(num_outputs);
    
    for i in 0..num_outputs {
        let mut h = Hasher::new_keyed(chaining_key);
        if i > 0 {
            h.update(&outputs[i-1]);
        }
        h.update(input_key_material);
        h.update(&[i as u8]);
        
        let output: [u8; 32] = *h.finalize().as_bytes();
        outputs.push(output);
    }
    
    outputs
}
