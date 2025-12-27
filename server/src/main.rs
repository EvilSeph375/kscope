use kscope::protocol::handshake::Handshake;
use kscope::protocol::transport::SecureTransport;
use kscope::net::tun::create_tun;

use std::net::UdpSocket;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let addr = "0.0.0.0:9000";

    let server_static = [2u8; 32];
    let psk = [9u8; 32];

    let socket = UdpSocket::bind(addr)?;
    println!("Server listening on {}", addr);

    let mut buf = [0u8; 2048];

    let mut peer = None;
    let client_static = [1u8; 32];

    let mut handshake = Handshake::new_responder(
        &server_static,
        &client_static,
        &psk
    )?;

    // ===== Noise Handshake =====
    while !handshake.is_complete() {
        let (len, p) = socket.recv_from(&mut buf)?;
        peer = Some(p);

        handshake.process_inbound(&buf[..len])?;

        if !handshake.is_complete() {
            let out_len = handshake.next_outbound(&mut buf)?;
            if out_len > 0 {
                socket.send_to(&buf[..out_len], p)?;
            }
        }
    }

    let peer = peer.unwrap();
    let session = handshake.into_session();
    let mut transport = SecureTransport::new(session);

    println!("Secure tunnel established.");

    // ===== Create TUN =====
    let tun = create_tun("kscope0")?;
    println!("TUN ready.");

    let mut tun_buf = [0u8; 1500];
    let mut net_buf = [0u8; 2048];

    // ===== VPN BRIDGE LOOP =====
    loop {
        // 1. Read IP from TUN
        let ip_len = tun.recv(&mut tun_buf)?;

        // 2. Encrypt
        let enc_len = transport.encrypt_frame(&tun_buf[..ip_len], &mut net_buf)?;

        // 3. Send via UDP
        socket.send_to(&net_buf[..enc_len], peer)?;

        // 4. Receive from UDP
        let (recv_len, _) = socket.recv_from(&mut net_buf)?;

        // 5. Decrypt
        let dec_len = transport.decrypt_frame(&net_buf[..recv_len], &mut tun_buf)?;

        // 6. Write back to TUN
        tun.send(&tun_buf[..dec_len])?;
    }
}
