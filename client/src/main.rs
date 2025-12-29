use kscope::protocol::handshake::Handshake;
use kscope::protocol::transport::SecureTransport;
use kscope::net::tun::create_tun;

use std::net::UdpSocket;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let _tun = create_tun("kscope0")?;
    println!("Client TUN created");

    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect("192.168.137.128:9000")?;

    let client_static = [1u8; 32];
    let server_static = [2u8; 32];
    let psk = [9u8; 32];

    let mut hs = Handshake::new_initiator(&client_static, &server_static, &psk)?;

    let mut net_buf = [0u8; 2048];

    println!("Starting handshake...");

    // ====== CORRECT HANDSHAKE LOOP ======
    loop {
        if let Ok(out_len) = hs.next_outbound(&mut net_buf) {
            if out_len > 0 {
                socket.send(&net_buf[..out_len])?;
            }
        }

        if hs.is_complete() {
            break;
        }

        let len = socket.recv(&mut net_buf)?;
        hs.process_inbound(&net_buf[..len])?;
    }

    println!("Handshake complete.");

    let session = hs.into_session();
    let mut transport = SecureTransport::new(session);

    let mut tun_buf = [0u8; 1500];

    println!("VPN active.");

    // ====== VPN BRIDGE ======
    loop {
        let ip_len = transport.recv_tun(&mut tun_buf)?;
        let enc_len = transport.encrypt_frame(&tun_buf[..ip_len], &mut net_buf)?;
        socket.send(&net_buf[..enc_len])?;

        let len = socket.recv(&mut net_buf)?;
        let dec_len = transport.decrypt_frame(&net_buf[..len], &mut tun_buf)?;
        transport.send_tun(&tun_buf[..dec_len])?;
    }
}
