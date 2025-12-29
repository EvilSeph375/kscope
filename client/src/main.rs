use kscope::protocol::handshake::Handshake;
use kscope::net::tun::create_tun;
use std::net::UdpSocket;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let _tun = create_tun("kscope0")?;
    println!("TUN interface kscope0 created");
    println!("Client TUN created");

    let server = "192.168.38.127:9000";
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect(server)?;

    // Твои ключи как и раньше
    let static_priv = [1u8; 32];
    let static_pub  = [2u8; 32];
    let psk         = [9u8; 32];

    let mut hs = Handshake::new_initiator(&static_priv, &static_pub, &psk)?;

    println!("Starting handshake...");

    let mut buf = [0u8; 2048];

    // 1️⃣ Клиент отправляет первый пакет
    let len = hs.next_outbound(&mut buf)?;
    socket.send(&buf[..len])?;

    // 2️⃣ Получает ответ сервера
    let n = socket.recv(&mut buf)?;
    hs.process_inbound(&buf[..n])?;

    // 3️⃣ Гарантированно получаем финальный пакет
    let len = loop {
        let out = hs.next_outbound(&mut buf)?;
        if out > 0 { break out; }
    };

    socket.send(&buf[..len])?;

    println!("Handshake complete.");

    Ok(())
}
