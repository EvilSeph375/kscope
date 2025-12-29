use kscope::protocol::handshake::Handshake;
use kscope::protocol::transport::SecureTransport;
use kscope::net::tun::create_tun;

use std::net::UdpSocket;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let server_static = [2u8; 32];
    let client_static = [1u8; 32];
    let psk = [9u8; 32];

    // 1. Create TUN first
    let tun = create_tun("kscope0")?;
    println!("TUN interface kscope0 created");

    // 2. UDP socket
    let socket = UdpSocket::bind("0.0.0.0:9000")?;
    println!("Server listening on 0.0.0.0:9000");
    println!("Waiting for client handshake...");

    // 3. Handshake
    let mut handshake = Handshake::new_responder(&server_static, &client_static, &psk)?;
    let mut buf = [0u8; 2048];
    let mut peer = None;

    while !handshake.is_complete() {
        let (len, addr) = socket.recv_from(&mut buf)?;
        peer = Some(addr);

        handshake.process_inbound(&buf[..len])?;

        if !handshake.is_complete() {
            let out_len = handshake.next_outbound(&mut buf)?;
            if out_len > 0 {
                socket.send_to(&buf[..out_len], addr)?;
            }
        }
    }

    let peer = peer.unwrap();
    println!("Handshake complete");

    let session = handshake.into_session();
    let mut transport = SecureTransport::new(session);

    // 4. VPN bridge
    let mut tun_buf = [0u8; 1500];
    let mut net_buf = [0u8; 2048];

    loop {
        let ip_len = tun.recv(&mut tun_buf)?;
        let enc_len = transport.encrypt_frame(&tun_buf[..ip_len], &mut net_buf)?;
        socket.send_to(&net_buf[..enc_len], peer)?;

        let (recv_len, _) = socket.recv_from(&mut net_buf)?;
        let dec_len = transport.decrypt_frame(&net_buf[..recv_len], &mut tun_buf)?;
        tun.send(&tun_buf[..dec_len])?;
    }
}
