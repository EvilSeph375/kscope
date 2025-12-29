use kscope::protocol::handshake::Handshake;
use kscope::protocol::transport::SecureTransport;
use kscope::net::tun::create_tun;

use std::net::{UdpSocket, SocketAddr};
use std::time::Duration;
use std::fs;

use serde::Deserialize;

#[derive(Deserialize)]
struct ClientConfig {
    server_addr: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cfg: ClientConfig = toml::from_str(&fs::read_to_string("config/client.toml")?)?;

    let server: SocketAddr = cfg.server_addr.parse()?;

    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_read_timeout(Some(Duration::from_secs(5)))?;

    let tun = create_tun("kscope0")?;
    println!("Client TUN created");

    let static_priv = [1u8; 32];
    let static_pub  = [2u8; 32];
    let psk         = [9u8; 32];

    let mut hs = Handshake::new_initiator(&static_priv, &static_pub, &psk)?;

    println!("Starting handshake...");

    let mut buf = [0u8; 2048];

    loop {
        let len = hs.next_outbound(&mut buf)?;
        if len > 0 {
            socket.send_to(&buf[..len], server)?;
        }

        if hs.is_complete() {
            break;
        }

        let (n, _) = socket.recv_from(&mut buf)?;
        hs.process_inbound(&buf[..n])?;
    }

    println!("Handshake complete.");

    let mut transport = SecureTransport::new(hs.into_session());

    let mut tun_buf = [0u8; 2000];
    let mut net_buf = [0u8; 2000];
    let mut crypt_buf = [0u8; 2000];

    loop {
        let n = tun.recv(&mut tun_buf)?;
        let enc = transport.encrypt_frame(&tun_buf[..n], &mut crypt_buf)?;
        socket.send_to(&crypt_buf[..enc], server)?;

        let (n, _) = socket.recv_from(&mut net_buf)?;
        let dec = transport.decrypt_frame(&net_buf[..n], &mut crypt_buf)?;
        tun.send(&crypt_buf[..dec])?;
    }
}

