pub mod crypto;
pub mod protocol;

use std::fmt;

#[derive(Debug)]
pub enum KScopeError {
    Protocol(String),
    Crypto(String),
    Io(String),
}

impl fmt::Display for KScopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KScopeError::Protocol(s) => write!(f, "Protocol error: {}", s),
            KScopeError::Crypto(s) => write!(f, "Crypto error: {}", s),
            KScopeError::Io(s) => write!(f, "IO error: {}", s),
        }
    }
}

impl std::error::Error for KScopeError {}

pub type Result<T> = std::result::Result<T, KScopeError>;
