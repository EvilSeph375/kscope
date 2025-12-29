use kscope::protocol::handshake::Handshake;
use kscope::net::tun::create_tun;
use std::net::UdpSocket;
use std::error::Error;
use base64::{engine::general_purpose, Engine as _};

fn main() -> Result<(), Box<dyn Error>> {
    let _tun = create_tun("kscope0")?;
    println!("TUN interface kscope0 created");

    let socket = UdpSocket::bind("0.0.0.0:9000")?;
    println!("Server listening on 0.0.0.0:9000");
    println!("Waiting for client handshake...");

    // ⬇️ ВСТАВИ СВОИ КЛЮЧИ
    let static_priv = general_purpose::STANDARD.decode("SHB+t/hY9/oMYxfhf+n/N8+Kegvtsw9EqpycJG8+JeU=")?;
    let client_pub  = general_purpose::STANDARD.decode("QPjQZPYKOFRKhnNoN1gAMqEGoU1HXhY3h40F3T78jmU=")?;
    let psk = [9u8; 32];

    let mut hs = Handshake::new_responder(&static_priv, &client_pub, &psk)?;

    let mut buf = [0u8; 2048];

    // msg1 от клиента
    // 1️⃣ Получаем msg1 от клиента
let (n, peer) = socket.recv_from(&mut buf)?;
println!("Received {} bytes from {}", n, peer);
hs.process_inbound(&buf[..n])?;


    // msg2 сервер → клиент
    let len = loop {
        let out = hs.next_outbound(&mut buf)?;
        if out > 0 { break out; }
    };
    socket.send_to(&buf[..len], peer)?;

    // msg3 от клиента
    let (n, _) = socket.recv_from(&mut buf)?;
    hs.process_inbound(&buf[..n])?;

    println!("Handshake complete with {}", peer);

    Ok(())
}
