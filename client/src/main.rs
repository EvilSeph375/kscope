use kscope::protocol::handshake::Handshake;
use kscope::net::tun::create_tun;
use std::net::UdpSocket;
use std::error::Error;
use base64::{engine::general_purpose, Engine as _};

fn main() -> Result<(), Box<dyn Error>> {
    let _tun = create_tun("kscope0")?;
    println!("TUN interface kscope0 created");
    println!("Client TUN created");

    let server = "192.168.38.127:9000";
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect(server)?;

    // ⬇️ ВСТАВИ СВОИ КЛЮЧИ
    let static_priv = general_purpose::STANDARD.decode("CLIENT_PRIVATE_BASE64")?;
    let server_pub  = general_purpose::STANDARD.decode("Server_public")?;
    let psk = [9u8; 32];

    let mut hs = Handshake::new_initiator(&static_priv, &server_pub, &psk)?;

    println!("Starting handshake...");

    let mut buf = [0u8; 2048];

    // msg1
    let len = hs.next_outbound(&mut buf)?;
    socket.send(&buf[..len])?;

    // msg2
    let n = socket.recv(&mut buf)?;
    hs.process_inbound(&buf[..n])?;

    // msg3
    let len = loop {
        let out = hs.next_outbound(&mut buf)?;
        if out > 0 { break out; }
    };
    socket.send(&buf[..len])?;

    println!("Handshake complete.");

    Ok(())
}
