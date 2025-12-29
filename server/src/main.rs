use kscope::protocol::handshake::Handshake;
use kscope::net::tun::create_tun;
use std::net::UdpSocket;
use std::error::Error;
use base64::{engine::general_purpose, Engine as _};
use std::io::{Read, Write};

fn main() -> Result<(), Box<dyn Error>> {
    let mut tun = create_tun("kscope0")?;
    println!("Server TUN created");

    let socket = UdpSocket::bind("0.0.0.0:9000")?;
    println!("Listening on 0.0.0.0:9000");

    // 🔐 КЛЮЧИ
    let static_priv = general_purpose::STANDARD.decode("SHB+t/hY9/oMYxfhf+n/N8+Kegvtsw9EqpycJG8+JeU=")?;
    let client_pub  = general_purpose::STANDARD.decode("QPjQZPYKOFRKhnNoN1gAMqEGoU1HXhY3h40F3T78jmU=")?;
    let psk = [9u8; 32];

    let mut hs = Handshake::new_responder(&static_priv, &client_pub, &psk)?;

    let mut buf = [0u8; 4096];

    let (n, peer) = socket.recv_from(&mut buf)?;
    hs.process_inbound(&buf[..n])?;

    let len = hs.next_outbound(&mut buf)?;
    socket.send_to(&buf[..len], peer)?;

    let (n, _) = socket.recv_from(&mut buf)?;
    hs.process_inbound(&buf[..n])?;

    println!("Handshake complete.");
    let mut session = hs.into_session();

    let mut tun_buf = [0u8; 2000];
    let mut net_buf = [0u8; 2000];

    loop {
        // UDP → TUN
        let (n, _) = socket.recv_from(&mut net_buf)?;
        let decrypted = session.decrypt(&net_buf[..n])?;
        tun.write_all(&decrypted)?;

        // TUN → UDP
        let n = tun.read(&mut tun_buf)?;
        let encrypted = session.encrypt(&tun_buf[..n])?;
        socket.send_to(&encrypted, peer)?;
    }
}
