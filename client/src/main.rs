use kscope::protocol::handshake::Handshake;
use kscope::protocol::transport::SecureTransport;
use kscope::net::tun::create_tun;

use std::net::{UdpSocket, SocketAddr};
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let server: SocketAddr = "192.168.38.127:9000".parse()?;

    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_read_timeout(Some(Duration::from_secs(2)))?;
    socket.set_write_timeout(Some(Duration::from_secs(2)))?;

    let tun = create_tun("kscope0")?;
    println!("Client TUN created");

    // Временно жёстко заданные ключи — чтобы всё стабилизировать
    let static_priv = [1u8; 32];
    let static_pub  = [2u8; 32];
    let psk         = [9u8; 32];

    let mut hs = Handshake::new_initiator(&static_priv, &static_pub, &psk)?;

    println!("Starting handshake...");

    let mut buf = [0u8; 2048];

    // ===== Handshake =====
    loop {
        let out_len = hs.next_outbound(&mut buf)?;
        if out_len > 0 {
            socket.send_to(&buf[..out_len], server)?;
        }

        if hs.is_complete() {
            break;
        }

        match socket.recv_from(&mut buf) {
            Ok((n, _)) => hs.process_inbound(&buf[..n])?,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e.into()),
        }
    }

    println!("Handshake complete");

    let mut transport = SecureTransport::new(hs.into_session());

    let mut tun_buf   = [0u8; 2000];
    let mut net_buf   = [0u8; 2000];
    let mut crypt_buf = [0u8; 2000];

    println!("Entering transport loop");

    loop {
        // TUN → UDP
        let n = tun.recv(&mut tun_buf)?;
        let enc = transport.encrypt_frame(&tun_buf[..n], &mut crypt_buf)?;
        socket.send_to(&crypt_buf[..enc], server)?;

        // UDP → TUN
        let (n, _) = socket.recv_from(&mut net_buf)?;
        let dec = transport.decrypt_frame(&net_buf[..n], &mut crypt_buf)?;
        tun.send(&crypt_buf[..dec])?;
    }
}
