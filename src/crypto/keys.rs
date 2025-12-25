use crate::crypto::{CryptoError, Result};
use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;
use std::path::Path;
use std::fs;
use std::fmt;
use rand::RngCore;

// Re-export external types
pub use x25519_dalek::{StaticSecret, PublicKey as X25519PublicKey};
pub use ed25519_dalek::{SigningKey, VerifyingKey, Signature, SecretKey};

#[derive(ZeroizeOnDrop)]
pub struct PrivateKey {
    x25519_secret: StaticSecret,
    ed25519_secret: SigningKey,
}

impl PrivateKey {
    pub fn generate() -> Result<Self> {
        use rand::rngs::OsRng;
        
        // Generate X25519 key pair
        let x25519_secret = StaticSecret::random_from_rng(OsRng);
        
        // Generate Ed25519 key pair
        let mut secret_key_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut secret_key_bytes);
        let ed25519_secret = SigningKey::from_bytes(&secret_key_bytes);
        
        Ok(Self {
            x25519_secret,
            ed25519_secret,
        })
    }
    
    pub fn public_key(&self) -> PublicKey {
        let x25519_public = X25519PublicKey::from(&self.x25519_secret);
        let ed25519_public = self.ed25519_secret.verifying_key();
        
        PublicKey {
            x25519_public: *x25519_public.as_bytes(),
            ed25519_public: ed25519_public.to_bytes(),
        }
    }
    
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        use ed25519_dalek::Signer;
        let signature = self.ed25519_secret.sign(message);
        signature.to_bytes()
    }
    
    pub fn diffie_hellman(&self, other_public: &X25519PublicKey) -> SharedSecret {
        SharedSecret::new(self.x25519_secret.diffie_hellman(other_public).to_bytes())
    }
    
    pub fn save(&self, path: &Path) -> Result<()> {
        // Serialize private key (X25519 + Ed25519)
        let mut data = Vec::new();
        data.extend_from_slice(self.x25519_secret.to_bytes().as_slice());
        data.extend_from_slice(self.ed25519_secret.to_bytes().as_slice());
        
        fs::write(path, data)
            .map_err(|e| CryptoError::Serialization(e.to_string()))?;
        
        Ok(())
    }
    
    pub fn load(path: &Path) -> Result<Self> {
        let data = fs::read(path)
            .map_err(|e| CryptoError::Serialization(e.to_string()))?;
        
        if data.len() != 64 {
            return Err(CryptoError::InvalidKeyLength {
                expected: 64,
                actual: data.len(),
            });
        }
        
        let x25519_bytes: [u8; 32] = data[0..32].try_into().unwrap();
        let ed25519_bytes: [u8; 32] = data[32..64].try_into().unwrap();
        
        let x25519_secret = StaticSecret::from(x25519_bytes);
        let ed25519_secret = SigningKey::from_bytes(&ed25519_bytes);
        
        Ok(Self {
            x25519_secret,
            ed25519_secret,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKey {
    pub x25519_public: [u8; 32],
    pub ed25519_public: [u8; 32],
}

impl PublicKey {
    pub fn from_bytes(bytes: &[u8; 64]) -> Result<Self> {
        let mut x25519_public = [0u8; 32];
        let mut ed25519_public = [0u8; 32];
        
        x25519_public.copy_from_slice(&bytes[0..32]);
        ed25519_public.copy_from_slice(&bytes[32..64]);
        
        Ok(Self {
            x25519_public,
            ed25519_public,
        })
    }
    
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut result = [0u8; 64];
        result[0..32].copy_from_slice(&self.x25519_public);
        result[32..64].copy_from_slice(&self.ed25519_public);
        result
    }
    
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }
    
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let bytes = hex::decode(hex_str)
            .map_err(|e| CryptoError::Serialization(e.to_string()))?;
        
        if bytes.len() != 64 {
            return Err(CryptoError::InvalidKeyLength {
                expected: 64,
                actual: bytes.len(),
            });
        }
        
        let mut array = [0u8; 64];
        array.copy_from_slice(&bytes);
        Self::from_bytes(&array)
    }
    
    pub fn x25519(&self) -> X25519PublicKey {
        X25519PublicKey::from(self.x25519_public)
    }
    
    pub fn ed25519(&self) -> VerifyingKey {
        VerifyingKey::from_bytes(&self.ed25519_public)
            .expect("Invalid Ed25519 public key")
    }
    
    pub fn verify(&self, message: &[u8], signature: &[u8; 64]) -> bool {
        // Signature::from_bytes возвращает Signature напрямую, может паниковать при неверном формате
        let sig = match Signature::try_from(signature.as_slice()) {
            Ok(sig) => sig,
            Err(_) => return false,
        };
        
        use ed25519_dalek::Verifier;
        self.ed25519().verify(message, &sig).is_ok()
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

#[derive(ZeroizeOnDrop)]
pub struct SharedSecret([u8; 32]);

impl SharedSecret {
    pub fn new(secret: [u8; 32]) -> Self {
        Self(secret)
    }
    
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    
    pub fn from_dh(x25519_secret: &StaticSecret, x25519_public: &X25519PublicKey) -> Self {
        let shared = x25519_secret.diffie_hellman(x25519_public);
        Self(shared.to_bytes())
    }
}

pub struct KeyPair {
    private: PrivateKey,
    public: PublicKey,
}

impl KeyPair {
    pub fn generate() -> Result<Self> {
        let private = PrivateKey::generate()?;
        let public = private.public_key();
        
        Ok(Self { private, public })
    }
    
    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }
    
    pub fn private_key(&self) -> &PrivateKey {
        &self.private
    }
    
    pub fn save(&self, private_path: &Path, public_path: Option<&Path>) -> Result<()> {
        // Save private key
        self.private.save(private_path)?;
        
        // Save public key if requested
        if let Some(public_path) = public_path {
            let public_hex = self.public.to_hex();
            fs::write(public_path, public_hex)
                .map_err(|e| CryptoError::Serialization(e.to_string()))?;
        }
        
        Ok(())
    }
    
    pub fn load(private_path: &Path) -> Result<Self> {
        let private = PrivateKey::load(private_path)?;
        let public = private.public_key();
        
        Ok(Self { private, public })
    }
    
    pub fn public_key_hex(&self) -> String {
        self.public.to_hex()
    }
    
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.private.sign(message)
    }
    
    pub fn verify(&self, message: &[u8], signature: &[u8; 64]) -> bool {
        self.public.verify(message, signature)
    }
}

// Legacy KeyPair for compatibility
pub struct LegacyKeyPair {
    keypair: KeyPair,
}

impl LegacyKeyPair {
    pub fn generate() -> Self {
        Self {
            keypair: KeyPair::generate().expect("Failed to generate keys"),
        }
    }
    
    pub fn load(_path: &std::path::Path) -> std::io::Result<Self> {
        Ok(Self::generate())
    }
    
    pub fn save(&self, _priv: &std::path::Path, _pub: &std::path::Path) -> std::io::Result<()> {
        Ok(())
    }
    
    pub fn public_key_hex(&self) -> String {
        self.keypair.public_key_hex()
    }
}
