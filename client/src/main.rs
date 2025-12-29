use kscope::protocol::handshake::Handshake;
use kscope::net::tun::create_tun;
use std::net::UdpSocket;
use std::error::Error;
use base64::{engine::general_purpose, Engine as _};
use std::io::{Read, Write};

fn main() -> Result<(), Box<dyn Error>> {
    let mut tun = create_tun("kscope0")?;
    println!("Client TUN created");

    let server = "192.168.38.127:9000";
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect(server)?;

    // 🔐 КЛЮЧИ
    let static_priv = general_purpose::STANDARD.decode("tE5rhRO6dvugqLRXNOIk2BVP8vjssUR8bB14NkWtj9Q=")?;
    let server_pub  = general_purpose::STANDARD.decode("UGZ0fwnPh6gDdRL0UBsH0MSqJg5cnQ8cEozYJ0Zg3Sg=")?;
    let psk = [9u8; 32];

    let mut hs = Handshake::new_initiator(&static_priv, &server_pub, &psk)?;
    println!("Starting handshake...");

    let mut buf = [0u8; 4096];

    let len = hs.next_outbound(&mut buf)?;
    socket.send(&buf[..len])?;

    let n = socket.recv(&mut buf)?;
    hs.process_inbound(&buf[..n])?;

    let len = hs.next_outbound(&mut buf)?;
    socket.send(&buf[..len])?;

    println!("Handshake complete.");
    let mut session = hs.into_session();

    let mut tun_buf = [0u8; 2000];
    let mut net_buf = [0u8; 2000];

    loop {
        // TUN → UDP
        let n = tun.read(&mut tun_buf)?;
        let encrypted = session.encrypt(&tun_buf[..n])?;
        socket.send(&encrypted)?;

        // UDP → TUN
        let n = socket.recv(&mut net_buf)?;
        let decrypted = session.decrypt(&net_buf[..n])?;
        tun.write_all(&decrypted)?;
    }
}
