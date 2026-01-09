use std::net::SocketAddr;
use bytes::Bytes;
use kscope::crypto::keyfile::load_keys;
use kscope::protocol::{
    handshake::Handshake,
    packet::{Packet, TransportData},
    transport::SecureTransport,
};
use kscope::tun::{TunConfig, TunDevice};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let keys = load_keys("keys/server.keys");

    let mut tun = TunDevice::create(TunConfig {
        name: "kscope0".into(),
        ip: "10.8.0.1".parse()?,
        prefix_len: 24,
        mtu: 1400,
    })?;

    let sock = std::net::UdpSocket::bind("0.0.0.0:7000")?;
    let mut peer: Option<SocketAddr> = None;

    let mut hs = Handshake::new_responder(&keys.private, &keys.peer_public, &keys.psk)?;
    let mut buf = [0u8; 2048];

    // Handshake
    while !hs.is_complete() {
        let (n, addr) = sock.recv_from(&mut buf)?;
        peer = Some(addr);
        hs.process_inbound(&buf[..n])?;
        let n = hs.next_outbound(&mut buf)?;
        if n > 0 {
            sock.send_to(&buf[..n], addr)?;
        }
    }

    let mut transport = SecureTransport::new(hs.into_session());
    println!("Server: handshake complete");

    loop {
        // UDP → TUN
        if let Ok((n, _)) = sock.recv_from(&mut buf) {
            let (pkt, _) = Packet::deserialize(&buf[..n])?;
            if let Packet::TransportData(TransportData { ciphertext, .. }) = pkt {
                let mut plain = vec![0u8; ciphertext.len()];
                let len = transport.decrypt(&ciphertext, &mut plain)?;
                tun.write(&plain[..len])?;
            }
        }

        // TUN → UDP
        let data = tun.read()?;
        let mut encrypted = vec![0u8; data.len() + 64];
        let len = transport.encrypt(&data, &mut encrypted)?;

        let pkt = Packet::TransportData(TransportData {
            nonce: 0,
            ciphertext: Bytes::copy_from_slice(&encrypted[..len]),
        });

        let out = pkt.serialize(0);
        sock.send_to(&out, peer.unwrap())?;
    }
}
