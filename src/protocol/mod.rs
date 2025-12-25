pub mod packet;
pub mod transport;
pub mod handshake;

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub server: ServerSettings,
    pub network: NetworkSettings,
    pub logging: LoggingSettings,
    pub advanced: AdvancedSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerSettings {
    pub listen_addr: String,
    pub private_key: PathBuf,
    pub public_key: Option<PathBuf>,
    pub max_connections: usize,
    pub session_timeout: u64,
    pub keepalive_interval: u64,
    pub keepalive_timeout: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    pub client: ClientSettings,
    pub network: NetworkSettings,
    pub logging: LoggingSettings,
    pub advanced: AdvancedSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientSettings {
    pub server_addr: String,
    pub private_key: PathBuf,
    pub server_public_key: PathBuf,
    pub client_id: Option<String>,
    pub connection_timeout: u64,
    pub auto_reconnect: bool,
    pub reconnect_delay: u64,
    pub max_reconnect_attempts: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSettings {
    pub tun_name: String,
    pub tun_ip: String,
    pub mtu: u16,
    #[serde(default)]
    pub ip_forwarding: bool,
    #[serde(default)]
    pub dns_servers: Vec<String>,
    #[serde(default)]
    pub allowed_ips: Vec<String>,
    #[serde(default)]
    pub routes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingSettings {
    pub level: String,
    #[serde(default)]
    pub file: Option<PathBuf>,
    #[serde(default)]
    pub json_format: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvancedSettings {
    #[serde(default = "default_congestion_control")]
    pub congestion_control: String,
    #[serde(default = "default_init_cwnd")]
    pub init_cwnd: u32,
    #[serde(default = "default_max_packet_size")]
    pub max_packet_size: u16,
    #[serde(default = "default_enable_buffering")]
    pub enable_buffering: bool,
    #[serde(default = "default_buffer_size")]
    pub buffer_size: usize,
    #[serde(default = "default_enable_pmtud")]
    pub enable_pmtud: bool,
    #[serde(default)]
    pub enable_obfuscation: bool,
    #[serde(default)]
    pub obfuscation_mode: String,
    #[serde(default)]
    pub enable_compression: bool,
    #[serde(default = "default_compression_level")]
    pub compression_level: u32,
}

fn default_congestion_control() -> String { "bbr".to_string() }
fn default_init_cwnd() -> u32 { 10 }
fn default_max_packet_size() -> u16 { 1500 }
fn default_enable_buffering() -> bool { true }
fn default_buffer_size() -> usize { 1024 }
fn default_enable_pmtud() -> bool { true }
fn default_compression_level() -> u32 { 6 }
