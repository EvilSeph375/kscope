use std::net::UdpSocket;

use kscope::crypto::keyfile::load_keys;
use kscope::protocol::handshake::Handshake;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let keys = load_keys("keys/server.keys");
    let sock = UdpSocket::bind("0.0.0.0:7000")?;

    let mut hs = Handshake::new_responder(&keys.private, &keys.psk)?;
    let mut buf = [0u8; 2048];
    let mut peer = None;

    loop {
        let (n, addr) = sock.recv_from(&mut buf)?;
        peer = Some(addr);

        hs.process_inbound(&buf[..n])?;

        if !hs.is_complete() {
            let out = hs.next_outbound(&mut buf)?;
            if out > 0 {
                sock.send_to(&buf[..out], peer.unwrap())?;
            }
        }

        if hs.is_complete() {
            println!("Server: handshake complete");
            break;
        }
    }

    Ok(())
}
