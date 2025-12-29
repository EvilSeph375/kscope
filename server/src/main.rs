use kscope::protocol::handshake::Handshake;
use kscope::net::tun::create_tun;
use std::net::UdpSocket;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let _tun = create_tun("kscope0")?;
    println!("TUN interface kscope0 created");

    let socket = UdpSocket::bind("0.0.0.0:9000")?;
    println!("Server listening on 0.0.0.0:9000");
    println!("Waiting for client handshake...");

    let static_priv = [2u8; 32];
    let static_pub  = [1u8; 32];
    let psk         = [9u8; 32];

    let mut hs = Handshake::new_responder(&static_priv, &static_pub, &psk)?;

    let mut buf = [0u8; 2048];

    // 1️⃣ Получаем первый пакет клиента
    let (n, peer) = socket.recv_from(&mut buf)?;
    hs.process_inbound(&buf[..n])?;

    // 2️⃣ Генерируем ответ — КРУТИМСЯ, пока он реально появится
    let len = loop {
        let out = hs.next_outbound(&mut buf)?;
        if out > 0 { break out; }
    };

    socket.send_to(&buf[..len], peer)?;

    println!("Handshake complete with {}", peer);

    Ok(())
}
