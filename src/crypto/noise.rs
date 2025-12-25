use crate::crypto::{CryptoError, Result, blake3_hash, hkdf};
use crate::crypto::keys::{KeyPair, PublicKey, X25519PublicKey};
use zeroize::ZeroizeOnDrop;

const PROTOCOL_NAME: &[u8] = b"Noise_IK_25519_ChaChaPoly_BLAKE3";

#[derive(Debug, Clone)]
pub struct HandshakeResult {
    pub session_keys: SessionKeys,
    pub handshake_hash: [u8; 32],
}

#[derive(Debug, Clone, ZeroizeOnDrop)]
pub struct SessionKeys {
    pub send_key: [u8; 32],
    pub receive_key: [u8; 32],
    pub send_nonce: u64,
    pub receive_nonce: u64,
}

impl SessionKeys {
    pub fn new(send_key: [u8; 32], receive_key: [u8; 32]) -> Self {
        Self {
            send_key,
            receive_key,
            send_nonce: 0,
            receive_nonce: 0,
        }
    }
    
    pub fn encrypt(&mut self, plaintext: &[u8], additional_data: &[u8]) -> Result<Vec<u8>> {
        crate::crypto::encrypt(&self.send_key, self.send_nonce, plaintext, additional_data)
    }
    
    pub fn decrypt(&mut self, ciphertext: &[u8], additional_data: &[u8]) -> Result<Vec<u8>> {
        crate::crypto::decrypt(&self.receive_key, self.receive_nonce, ciphertext, additional_data)
    }
}

#[derive(Debug, Clone)]
pub enum HandshakeState {
    Initiated,
    Responded,
    Completed(HandshakeResult),
    Failed,
}

pub struct NoiseHandshake {
    state: HandshakeState,
    chaining_key: [u8; 32],
    hash: [u8; 32],
    ephemeral_key: Option<x25519_dalek::StaticSecret>,
    remote_static_public: Option<PublicKey>,
}

impl NoiseHandshake {
    pub fn initiator(_local_static: &KeyPair, remote_static_public: &PublicKey) -> Result<Self> {
        // Initialize chaining key and hash
        let mut chaining_key = [0u8; 32];
        let mut hash = [0u8; 32];
        
        // h = HASH(protocolName)
        let protocol_hash = blake3_hash(PROTOCOL_NAME);
        hash.copy_from_slice(&protocol_hash);
        
        // ck = protocolName
        chaining_key.copy_from_slice(&protocol_hash);
        
        // h = HASH(h || remote_static)
        let mut hasher = blake3::Hasher::new();
        hasher.update(&hash);
        hasher.update(&remote_static_public.to_bytes());
        hash.copy_from_slice(hasher.finalize().as_bytes());
        
        // Generate ephemeral key
        let ephemeral_key = x25519_dalek::StaticSecret::random_from_rng(rand::thread_rng());
        
        Ok(Self {
            state: HandshakeState::Initiated,
            chaining_key,
            hash,
            ephemeral_key: Some(ephemeral_key),
            remote_static_public: Some(remote_static_public.clone()),
        })
    }
    
    pub fn responder(_local_static: &KeyPair) -> Self {
        // Initialize chaining key and hash
        let mut chaining_key = [0u8; 32];
        let mut hash = [0u8; 32];
        
        // h = HASH(protocolName)
        let protocol_hash = blake3_hash(PROTOCOL_NAME);
        hash.copy_from_slice(&protocol_hash);
        
        // ck = protocolName
        chaining_key.copy_from_slice(&protocol_hash);
        
        Self {
            state: HandshakeState::Initiated,
            chaining_key,
            hash,
            ephemeral_key: None,
            remote_static_public: None,
        }
    }
    
    pub fn write_message(&mut self, _payload: &[u8]) -> Result<(Vec<u8>, HandshakeState)> {
        match &self.state {
            HandshakeState::Initiated => {
                // Initiator's first message
                let ephemeral_key = self.ephemeral_key.take()
                    .ok_or_else(|| CryptoError::Generic("No ephemeral key".to_string()))?;
                let ephemeral_public = x25519_dalek::PublicKey::from(&ephemeral_key);
                
                // e
                let mut message = Vec::new();
                message.extend_from_slice(ephemeral_public.as_bytes());
                
                // h = HASH(h || e)
                let mut hasher = blake3::Hasher::new();
                hasher.update(&self.hash);
                hasher.update(ephemeral_public.as_bytes());
                self.hash.copy_from_slice(hasher.finalize().as_bytes());
                
                // DH computations
                let remote_public = self.remote_static_public.as_ref()
                    .ok_or_else(|| CryptoError::Generic("No remote static public".to_string()))?;
                
                // es = ECDH(e, rs)
                let es = ephemeral_key.diffie_hellman(&remote_public.x25519());
                
                // ck, k = HKDF(ck, es)
                let keys = hkdf(&self.chaining_key, es.as_bytes(), 2);
                self.chaining_key.copy_from_slice(&keys[0]);
                let _temp_k = keys[1];
                
                // Update state
                self.state = HandshakeState::Responded;
                
                Ok((message, HandshakeState::Responded))
            }
            _ => Err(CryptoError::Generic("Invalid handshake state".to_string())),
        }
    }
    
    pub fn read_message(&mut self, message: &[u8], _payload: &[u8]) -> Result<(Vec<u8>, HandshakeState)> {
        match &self.state {
            HandshakeState::Initiated => {
                // Responder processing initiator's message
                if message.len() < 32 {
                    return Err(CryptoError::Generic("Message too short".to_string()));
                }
                
                let ephemeral_public_bytes: [u8; 32] = message[0..32].try_into().unwrap();
                let _ephemeral_public = X25519PublicKey::from(ephemeral_public_bytes);
                
                // Update hash
                let mut hasher = blake3::Hasher::new();
                hasher.update(&self.hash);
                hasher.update(&ephemeral_public_bytes);
                self.hash.copy_from_slice(hasher.finalize().as_bytes());
                
                // Generate responder's ephemeral key
                let responder_ephemeral = x25519_dalek::StaticSecret::random_from_rng(rand::thread_rng());
                let responder_public = x25519_dalek::PublicKey::from(&responder_ephemeral);
                
                // Prepare response
                let mut response = Vec::new();
                response.extend_from_slice(responder_public.as_bytes());
                
                // Update state (simplified)
                self.state = HandshakeState::Completed(HandshakeResult {
                    session_keys: SessionKeys::new([0u8; 32], [0u8; 32]), // Placeholder
                    handshake_hash: [0u8; 32],
                });
                
                Ok((response, HandshakeState::Completed(HandshakeResult {
                    session_keys: SessionKeys::new([0u8; 32], [0u8; 32]),
                    handshake_hash: [0u8; 32],
                })))
            }
            _ => Err(CryptoError::Generic("Invalid handshake state".to_string())),
        }
    }
    
    pub fn finalize(&mut self) -> Result<HandshakeResult> {
        match &self.state {
            HandshakeState::Completed(result) => Ok(result.clone()),
            _ => Err(CryptoError::Generic("Handshake not completed".to_string())),
        }
    }
}
