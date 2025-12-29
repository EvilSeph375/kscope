use kscope::protocol::handshake::Handshake;
use kscope::protocol::transport::SecureTransport;
use kscope::net::tun::create_tun;

use std::net::{UdpSocket, SocketAddr};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let socket = UdpSocket::bind("0.0.0.0:9000")?;
    let mut tun = create_tun("kscope0")?;

    println!("Server listening on 0.0.0.0:9000");
    println!("Waiting for client handshake...");

    let static_priv = [2u8; 32];
    let static_pub  = [1u8; 32];
    let psk         = [9u8; 32];

    let mut hs = Handshake::new_responder(&static_priv, &static_pub, &psk)?;

    let mut buf = [0u8; 2048];

    // === ШАГ 1: получаем msg1 ===
    let (n, peer) = socket.recv_from(&mut buf)?;
    hs.process_inbound(&buf[..n])?;

    // === ШАГ 2: отправляем msg2 ===
    let len = hs.next_outbound(&mut buf)?;
    socket.send_to(&buf[..len], peer)?;

    // === ШАГ 3: получаем msg3 ===
    let (n, _) = socket.recv_from(&mut buf)?;
    hs.process_inbound(&buf[..n])?;

    if !hs.is_complete() {
        return Err("Handshake did not complete".into());
    }

    println!("Handshake complete with {}", peer);

    let mut transport = SecureTransport::new(hs.into_session());

    let mut tun_buf = [0u8; 2000];
    let mut net_buf = [0u8; 2000];
    let mut crypt_buf = [0u8; 2000];

    loop {
        let (n, _) = socket.recv_from(&mut net_buf)?;
        let dec = transport.decrypt_frame(&net_buf[..n], &mut crypt_buf)?;
        tun.send(&crypt_buf[..dec])?;

        let n = tun.recv(&mut tun_buf)?;
        let enc = transport.encrypt_frame(&tun_buf[..n], &mut crypt_buf)?;
        socket.send_to(&crypt_buf[..enc], peer)?;
    }
}
