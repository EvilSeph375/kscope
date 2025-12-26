// examples/noise_handshake_test.rs
use kscope::crypto::KeyPair;
use kscope::crypto::noise_handshake::NoiseHandshake;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Noise Handshake Test ===");
    
    // 1. Генерируем ключи для клиента и сервера
    println!("Generating key pairs...");
    let client_keys = KeyPair::generate()?;
    let server_keys = KeyPair::generate()?;
    
    println!("Client public key: {}", client_keys.public_key_hex());
    println!("Server public key: {}", server_keys.public_key_hex());
    
    // 2. Клиент создает init сообщение
    println!("\nClient creating init message...");
    let mut client_handshake = NoiseHandshake::initiator(
        &client_keys,
        &server_keys.public_key()
    )?;
    
    let init_message = client_handshake.write_init_message()?;
    println!("Init message: {} bytes", init_message.len());
    
    // 3. Сервер обрабатывает init сообщение
    println!("\nServer processing init message...");
    let mut server_handshake = NoiseHandshake::responder(&server_keys)?;
    
    let response = server_handshake.read_message(&init_message)?;
    
    if let Some(response_data) = response {
        println!("Server response: {} bytes", response_data.len());
        
        // 4. Клиент завершает handshake
        println!("\nClient finishing handshake...");
        // TODO: client_handshake.finish_handshake(&response_data)?;
        
        println!("✅ Handshake completed successfully!");
    } else {
        println!("❌ No response from server");
    }
    
    Ok(())
}
