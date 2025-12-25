pub mod crypto;
pub mod protocol;
pub mod server;
pub mod tun;
pub mod client;

pub use crypto::LegacyKeyPair as KeyPair;

#[derive(thiserror::Error, Debug)]
pub enum KScopeError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Crypto error: {0}")]
    Crypto(#[from] crate::crypto::CryptoError),  // Добавляем #[from]
    #[error("Protocol error: {0}")]
    Protocol(String),
    #[error("Configuration error: {0}")]
    Config(String),
    #[error("Task error: {0}")]
    Task(#[from] tokio::task::JoinError),
}

pub type Result<T> = std::result::Result<T, KScopeError>;

// Реэкспорт для удобства
pub use client::KScopeClient;
