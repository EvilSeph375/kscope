use clap::{Parser, Subcommand};
use kscope::client::KScopeClient;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

// Добавим импорт правильного типа конфигурации
use kscope::protocol::ClientConfig;

#[derive(Parser)]
#[command(author, version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Connect to KScope VPN server
    Connect {
        /// Configuration file path
        #[arg(short, long, default_value = "~/.config/kscope/client.toml")]
        config: String,
    },

    /// Generate client keys
    GenKeys,

    /// Disconnect from VPN
    Disconnect,

    /// Show connection status
    Status,
}

/// Расширяет путь с ~ на домашнюю директорию
fn expand_home(path: &str) -> PathBuf {
    if path.starts_with('~') {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
        PathBuf::from(path.replacen("~", &home, 1))
    } else {
        PathBuf::from(path)
    }
}

/// Заменяет ~ в путях внутри TOML конфигурации
fn expand_paths_in_toml(content: &str) -> String {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
    content.replace("~", &home)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Настройка логирования
    env_logger::init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Connect { config } => {
            // Разворачиваем путь
            let config_path = expand_home(&config);
            
            println!("Loading configuration from {}...", config_path.display());
            
            // Проверяем существование файла
            if !config_path.exists() {
                eprintln!("Error: Configuration file not found at {}", config_path.display());
                eprintln!("Create a default config file with:");
                eprintln!("  mkdir -p ~/.config/kscope");
                eprintln!("  cp config/client.toml ~/.config/kscope/");
                return Ok(());
            }
            
            // Загружаем и обрабатываем конфигурацию
            let config_str = match std::fs::read_to_string(&config_path) {
                Ok(content) => content,
                Err(e) => {
                    eprintln!("Error reading config file: {}", e);
                    return Ok(());
                }
            };
            
            // Расширяем ~ в путях внутри TOML
            let expanded_config_str = expand_paths_in_toml(&config_str);
            
            let config: ClientConfig = match toml::from_str(&expanded_config_str) {
                Ok(config) => config,
                Err(e) => {
                    eprintln!("Error parsing config file: {}", e);
                    eprintln!("Make sure the config file is valid TOML format.");
                    return Ok(());
                }
            };
            
            println!("Successfully loaded configuration");
            println!("Connecting to server: {}", config.client.server_addr);
            
            // Создаем и запускаем клиент
            let client = match KScopeClient::new(config).await {
                Ok(client) => Arc::new(Mutex::new(client)),
                Err(e) => {
                    eprintln!("Error creating VPN client: {}", e);
                    return Ok(());
                }
            };
            
            let client_for_signal = Arc::clone(&client);

            // Обрабатываем Ctrl+C
            tokio::spawn(async move {
                tokio::signal::ctrl_c().await.expect("Failed to listen for Ctrl+C");
                println!("\nReceived Ctrl+C, disconnecting...");
                let mut client = client_for_signal.lock().await;
                client.disconnect().await.ok();
                std::process::exit(0);
            });

            let mut client_guard = client.lock().await;
            match client_guard.connect().await {
                Ok(_) => {
                    println!("Connected successfully!");
                    println!("Press Ctrl+C to disconnect");
                    
                    // Держим соединение активным
                    loop {
                        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                    }
                }
                Err(e) => {
                    eprintln!("Connection error: {}", e);
                }
            }
        }

        Commands::GenKeys => {
            println!("Generating client keys...");
            let keys = kscope::KeyPair::generate();
            println!("Public key: {}", keys.public_key_hex());

            // Создаем директорию для конфигов
            let home = std::env::var("HOME")?;
            let config_dir = PathBuf::from(home).join(".config/kscope");
            if let Err(e) = std::fs::create_dir_all(&config_dir) {
                eprintln!("Error creating config directory: {}", e);
                return Ok(());
            }

            // Сохраняем ключи
            let private_key_path = config_dir.join("client.key");
            let public_key_path = config_dir.join("client.pub");
            
            // Используем методы из LegacyKeyPair
            if let Err(e) = keys.save_to_file(&private_key_path) {
                eprintln!("Error saving private key: {}", e);
            } else {
                println!("Private key saved to: {}", private_key_path.display());
            }
            
            // Сохраняем публичный ключ
            let pub_key_str = keys.public_key_hex();
            if let Err(e) = std::fs::write(&public_key_path, pub_key_str) {
                eprintln!("Error saving public key: {}", e);
            } else {
                println!("Public key saved to: {}", public_key_path.display());
            }
        }

        Commands::Disconnect => {
            println!("Disconnecting...");
            // TODO: Реализовать отключение через IPC или сигнал
            println!("Disconnect command not implemented yet.");
        }

        Commands::Status => {
            println!("Status: Not connected");
            // TODO: Проверить состояние соединения через IPC
        }
    }

    Ok(())
}
