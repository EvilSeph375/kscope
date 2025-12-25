use clap::{Parser, Subcommand};
use kscope::protocol::ServerConfig;
use kscope::server::KScopeServer;
use std::path::PathBuf;

#[derive(Parser)]
#[command(author, version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the KScope VPN server
    Start {
        /// Configuration file path
        #[arg(short, long)]
        config: Option<PathBuf>,
    },
    
    /// Generate server keys
    GenKeys,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    
    match cli.command {
        Commands::Start { config: _ } => {
            println!("Starting KScope VPN server...");
            
            // Простая конфигурация для теста
            let config = ServerConfig {
                server: kscope::protocol::ServerSettings {
                    listen_addr: "0.0.0.0:51820".to_string(),
                    private_key: PathBuf::from("/tmp/test.key"),
                    public_key: None,
                    max_connections: 1024,
                    session_timeout: 3600,
                    keepalive_interval: 25,
                    keepalive_timeout: 90,
                },
                network: kscope::protocol::NetworkSettings {
                    tun_name: "kscope0".to_string(),
                    tun_ip: "10.0.0.1/24".to_string(),
                    mtu: 1420,
                    ip_forwarding: true,
                    dns_servers: vec![],
                    allowed_ips: vec![],
                    routes: vec![],
                },
                logging: kscope::protocol::LoggingSettings {
                    level: "info".to_string(),
                    file: None,
                    json_format: false,
                },
                advanced: kscope::protocol::AdvancedSettings {
                    congestion_control: "bbr".to_string(),
                    init_cwnd: 10,
                    max_packet_size: 1500,
                    enable_buffering: true,
                    buffer_size: 1024,
                    enable_pmtud: true,
                    enable_obfuscation: false,
                    obfuscation_mode: "none".to_string(),
                    enable_compression: false,
                    compression_level: 6,
                },
            };
            
            let mut server = KScopeServer::new(config).await?;
            server.run().await?;
        }
        
        Commands::GenKeys => {
            println!("Generating server keys...");
            // Используем LegacyKeyPair вместо KeyPair для совместимости
            let keys = kscope::KeyPair::generate();
            println!("Public key: {}", keys.public_key_hex());
        }
    }
    
    Ok(())
}
