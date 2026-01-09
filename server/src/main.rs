use std::net::SocketAddr;
//test
use bytes::Bytes;
use kscope::crypto::keyfile::load_keys;
use kscope::protocol::{
    handshake::Handshake,
    packet::{Packet, TransportData},
    transport::SecureTransport,
};
use kscope::tun::{TunConfig, TunDevice};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

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

    // === Handshake ===
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

    // === Data loop ===
    loop {
        let packet: Vec<u8> = tun.read()?;

        let mut encrypted = vec![0u8; packet.len() + 64];
        let len = transport.encrypt(&packet, &mut encrypted)?;

        let pkt = Packet::TransportData(TransportData {
            nonce: 0,
            ciphertext: Bytes::copy_from_slice(&encrypted[..len]),
        });

        let out = pkt.serialize(0);
        sock.send_to(&out, peer.unwrap())?;
    }
}
