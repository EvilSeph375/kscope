pub mod crypto;
pub mod protocol;
pub mod tun;

use std::fmt;

#[derive(Debug)]
pub enum KScopeError {
    Io(String),
    Protocol(String),
    Config(String),
}

impl From<std::io::Error> for KScopeError {
    fn from(e: std::io::Error) -> Self {
        KScopeError::Io(e.to_string())
    }
}

impl fmt::Display for KScopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KScopeError::Io(s) => write!(f, "IO error: {}", s),
            KScopeError::Protocol(s) => write!(f, "Protocol error: {}", s),
            KScopeError::Config(s) => write!(f, "Config error: {}", s),
        }
    }
}

impl std::error::Error for KScopeError {}

pub type Result<T> = std::result::Result<T, KScopeError>;
