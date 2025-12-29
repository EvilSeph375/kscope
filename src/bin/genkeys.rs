use kscope::crypto::keys::KeyPair;
use base64::{engine::general_purpose, Engine as _};

fn main() {
    let kp = KeyPair::generate();

    println!("PRIVATE={}", general_purpose::STANDARD.encode(kp.private.to_bytes()));
    println!("PUBLIC={}",  general_purpose::STANDARD.encode(kp.public.as_bytes()));
}
