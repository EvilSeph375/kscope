use kscope::crypto::keys::KeyPair;
use base64::{engine::general_purpose, Engine};
use rand::RngCore;

fn main() {
    let server = KeyPair::generate();
    let client = KeyPair::generate();

    let mut psk = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut psk);

    println!("--- server.keys ---");
    println!("PRIVATE={}", general_purpose::STANDARD.encode(server.private.to_bytes()));
    println!("PEER_PUBLIC={}", general_purpose::STANDARD.encode(client.public.as_bytes()));
    println!("PSK={}", general_purpose::STANDARD.encode(psk));

    println!("\n--- client.keys ---");
    println!("PRIVATE={}", general_purpose::STANDARD.encode(client.private.to_bytes()));
    println!("PEER_PUBLIC={}", general_purpose::STANDARD.encode(server.public.as_bytes()));
    println!("PSK={}", general_purpose::STANDARD.encode(psk));
}
