use kscope::protocol::handshake::Handshake;
use kscope::protocol::transport::SecureTransport;
use kscope::net::tun::create_tun;

use std::net::UdpSocket;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let server_addr = "127.0.0.1:9000";

    let client_static = [1u8; 32];
    let server_static = [2u8; 32];
    let psk = [9u8; 32];

    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect(server_addr)?;

    let mut handshake = Handshake::new_initiator(&client_static, &server_static, &psk)?;
    let mut buf = [0u8; 2048];

    // ===== Handshake =====
    while !handshake.is_complete() {
        let out_len = handshake.next_outbound(&mut buf)?;
        if out_len > 0 {
            socket.send(&buf[..out_len])?;
        }

        if handshake.is_complete() { break; }

        let recv_len = socket.recv(&mut buf)?;
        handshake.process_inbound(&buf[..recv_len])?;
    }

    let session = handshake.into_session();
    let mut transport = SecureTransport::new(session);

    println!("Secure tunnel established.");

    // ===== Create client TUN =====
    let mut tun = create_tun("kscope0")?;
    println!("Client TUN ready.");

    let mut tun_buf = [0u8; 1500];
    let mut net_buf = [0u8; 2048];

    // ===== VPN Bridge Loop =====
    loop {
        // 1. Read IP packet from TUN
        let ip_len = tun.recv(&mut tun_buf)?;

        // 2. Encrypt
        let enc_len = transport.encrypt_frame(&tun_buf[..ip_len], &mut net_buf)?;

        // 3. Send to server
        socket.send(&net_buf[..enc_len])?;

        // 4. Receive from server
        let recv_len = socket.recv(&mut net_buf)?;

        // 5. Decrypt
        let dec_len = transport.decrypt_frame(&net_buf[..recv_len], &mut tun_buf)?;

        // 6. Write back to TUN
        tun.send(&tun_buf[..dec_len])?;
    }
}
