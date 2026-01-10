use std::net::UdpSocket;
use bytes::Bytes;
use kscope::crypto::keyfile::load_keys;
use kscope::protocol::{handshake::Handshake, packet::{Packet, TransportData}, transport::SecureTransport};
use kscope::tun::{TunConfig, TunDevice};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let keys = load_keys("keys/client.keys");

    let mut tun = TunDevice::create(TunConfig {
        name: "kscope0".into(),
        ip: "10.8.0.2".parse()?,
        prefix_len: 24,
        mtu: 1400,
    })?;

    let sock = UdpSocket::bind("0.0.0.0:0")?;
    let server = "192.168.38.127:7000";

    let mut hs = Handshake::new_initiator(&keys.private, &keys.peer_public, &keys.psk)?;

    if let Some(pkt) = hs.next_outbound()? {
        sock.send_to(&pkt.serialize(0), server)?;
    }

    let mut buf = [0u8; 2048];

    loop {
        let (n, _) = sock.recv_from(&mut buf)?;
        let (pkt, _) = Packet::deserialize(&buf[..n])?;

        hs.process_inbound(pkt)?;

        if let Some(reply) = hs.next_outbound()? {
            sock.send_to(&reply.serialize(0), server)?;
        }

        if hs.is_complete() { break; }
    }

    println!("Client: handshake complete");

    let mut transport = SecureTransport::new(hs.into_session());

    loop {
        let (n, _) = sock.recv_from(&mut buf)?;
        let (pkt, _) = Packet::deserialize(&buf[..n])?;

        if let Packet::TransportData(TransportData { ciphertext, .. }) = pkt {
            let mut plain = vec![0u8; ciphertext.len()];
            let len = transport.decrypt(&ciphertext, &mut plain)?;
            tun.write(&plain[..len])?;
        }
    }
}

