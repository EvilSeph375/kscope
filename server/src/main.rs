use std::net::{UdpSocket, SocketAddr};
use kscope::crypto::keyfile::load_keys;
use kscope::protocol::handshake::Handshake;
use kscope::protocol::packet::{Packet, TransportData};
use kscope::protocol::transport::SecureTransport;
use kscope::tun::{TunConfig, TunDevice};
use bytes::Bytes;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let keys = load_keys("keys/server.keys");

    let mut tun = TunDevice::create(TunConfig {
        name: "kscope0".into(),
        ip: "10.8.0.1".parse()?,
        prefix_len: 24,
        mtu: 1400,
    })?;

    let sock = UdpSocket::bind("0.0.0.0:7000")?;
    let mut peer: SocketAddr;

    let mut hs = Handshake::new_responder(&keys.private, &keys.peer_public, &keys.psk)?;
    let mut buf = [0u8; 2048];

    // ===== Handshake =====
    let (n, addr) = sock.recv_from(&mut buf)?;
    peer = addr;
    hs.process_inbound(&buf[..n])?;

    let n = hs.next_outbound(&mut buf)?;
    sock.send_to(&buf[..n], peer)?;

    let (n, _) = sock.recv_from(&mut buf)?;
    hs.process_inbound(&buf[..n])?;

    println!("🔐 Server: handshake complete");

    let mut transport = SecureTransport::new(hs.into_session());

    // ===== Data loop =====
    loop {
        if let Ok(packet) = tun.read() {
            let mut encrypted = vec![0u8; packet.len() + 64];
            let len = transport.encrypt(&packet, &mut encrypted)?;

            let pkt = Packet::TransportData(TransportData {
                nonce: 0,
                ciphertext: Bytes::copy_from_slice(&encrypted[..len]),
            });

            sock.send_to(&pkt.serialize(0), peer)?;
        }

        if let Ok((n, _)) = sock.recv_from(&mut buf) {
            let (pkt, _) = Packet::deserialize(&buf[..n])?;
            if let Packet::TransportData(td) = pkt {
                let mut plain = vec![0u8; td.ciphertext.len()];
                let len = transport.decrypt(&td.ciphertext, &mut plain)?;
                tun.write(&plain[..len])?;
            }
        }
    }
}
