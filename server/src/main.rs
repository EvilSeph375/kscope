use kscope::protocol::handshake::Handshake;
use kscope::protocol::transport::SecureTransport;
use kscope::net::tun::create_tun;

use std::net::{UdpSocket, SocketAddr};
use std::fs;
use serde::Deserialize;

#[derive(Deserialize)]
struct ServerConfig {
    listen_addr: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cfg: ServerConfig = toml::from_str(&fs::read_to_string("config/server.toml")?)?;

    let socket = UdpSocket::bind(&cfg.listen_addr)?;
    let tun = create_tun("kscope0")?;

    println!("Server listening on {}", cfg.listen_addr);
    println!("Waiting for client handshake...");

    let static_priv = [2u8; 32];
    let static_pub  = [1u8; 32];
    let psk         = [9u8; 32];

    let mut hs = Handshake::new_responder(&static_priv, &static_pub, &psk)?;

    let mut buf = [0u8; 2048];
    let peer: SocketAddr;

    loop {
        let (n, addr) = socket.recv_from(&mut buf)?;
        hs.process_inbound(&buf[..n])?;

        let len = hs.next_outbound(&mut buf)?;
        if len > 0 {
            socket.send_to(&buf[..len], addr)?;
        }

        if hs.is_complete() {
            peer = addr;
            break;
        }
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
