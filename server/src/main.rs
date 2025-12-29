use kscope::protocol::handshake::Handshake;
use kscope::protocol::transport::SecureTransport;
use kscope::net::tun::create_tun;

use std::net::UdpSocket;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let _tun = create_tun("kscope0")?;
    println!("TUN interface kscope0 created");

    let socket = UdpSocket::bind("0.0.0.0:9000")?;
    socket.set_nonblocking(false)?;
    println!("Server listening on 0.0.0.0:9000");
    println!("Waiting for client handshake...");

    let server_static = [2u8; 32];
    let client_static = [1u8; 32];
    let psk = [9u8; 32];

    let mut hs = Handshake::new_responder(&server_static, &client_static, &psk)?;

    let mut net_buf = [0u8; 2048];
    let mut peer = None;

    // ====== CORRECT HANDSHAKE LOOP ======
    loop {
        let (len, p) = socket.recv_from(&mut net_buf)?;
        peer = Some(p);

        hs.process_inbound(&net_buf[..len])?;

        if let Ok(out_len) = hs.next_outbound(&mut net_buf) {
            if out_len > 0 {
                socket.send_to(&net_buf[..out_len], p)?;
            }
        }

        if hs.is_complete() {
            break;
        }
    }

    println!("Handshake complete.");

    let session = hs.into_session();
    let mut transport = SecureTransport::new(session);

    let peer = peer.unwrap();

    let mut tun_buf = [0u8; 1500];

    println!("VPN active.");

    // ====== VPN BRIDGE ======
    loop {
        let ip_len = transport.recv_udp(&socket, peer, &mut net_buf)?;
        let dec_len = transport.decrypt_frame(&net_buf[..ip_len], &mut tun_buf)?;
        transport.send_tun(&tun_buf[..dec_len])?;

        let ip_len = transport.recv_tun(&mut tun_buf)?;
        let enc_len = transport.encrypt_frame(&tun_buf[..ip_len], &mut net_buf)?;
        socket.send_to(&net_buf[..enc_len], peer)?;
    }
}
