use kscope::protocol::handshake::Handshake;
use kscope::protocol::transport::SecureTransport;
use kscope::net::tun::create_tun;

use std::net::UdpSocket;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {

    // --- Create TUN first ---
    let tun = create_tun("kscope0")?;
    println!("TUN interface kscope0 created");

    let addr = "0.0.0.0:9000";
    let socket = UdpSocket::bind(addr)?;
    println!("Server listening on {}", addr);
    println!("Waiting for client handshake...");

    let server_static = [2u8; 32];
    let client_static = [1u8; 32];
    let psk = [9u8; 32];

    let mut buf = [0u8; 2048];
    let mut peer = None;

    let mut handshake = Handshake::new_responder(
        &server_static,
        &client_static,
        &psk
    )?;

    // ===== Handshake =====
    while !handshake.is_complete() {
        let (len, p) = socket.recv_from(&mut buf)?;
        peer = Some(p);

        handshake.process_inbound(&buf[..len])?;

        if !handshake.is_complete() {
            let out_len = handshake.next_outbound(&mut buf)?;
            socket.send_to(&buf[..out_len], p)?;
        }
    }

    println!("Secure tunnel established.");

    let peer = peer.unwrap();
    let session = handshake.into_session();
    let mut transport = SecureTransport::new(session);

    let mut tun_buf = [0u8; 1500];
    let mut net_buf = [0u8; 2048];

    // ===== VPN bridge =====
    loop {
        let ip_len = tun.recv(&mut tun_buf)?;
        let enc_len = transport.encrypt_frame(&tun_buf[..ip_len], &mut net_buf)?;
        socket.send_to(&net_buf[..enc_len], peer)?;

        let (recv_len, _) = socket.recv_from(&mut net_buf)?;
        let dec_len = transport.decrypt_frame(&net_buf[..recv_len], &mut tun_buf)?;
        tun.send(&tun_buf[..dec_len])?;
    }
}
