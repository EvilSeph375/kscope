use std::net::{SocketAddr, UdpSocket};
use bytes::Bytes;
use kscope::crypto::keyfile::load_keys;
use kscope::protocol::handshake::Handshake;
use kscope::protocol::packet::{Packet, TransportData};
use kscope::protocol::transport::SecureTransport;
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

    let sock = UdpSocket::bind("0.0.0.0:7000")?;
    let mut hs = Handshake::new_responder(&keys.private, &keys.peer_public, &keys.psk)?;
    let mut buf = [0u8; 2048];

    let mut peer: SocketAddr;

    loop {
        let (n, addr) = sock.recv_from(&mut buf)?;
        peer = addr;

        hs.process_inbound(&buf[..n])?;

        let out = hs.next_outbound(&mut buf)?;
        if out > 0 {
            sock.send_to(&buf[..out], peer)?;
        }

        if hs.is_complete() {
            break;
        }
    }

    println!("Server: handshake complete");

    let mut transport = SecureTransport::new(hs.into_session());

    loop {
        let packet = tun.read()?;

        let mut encrypted = vec![0u8; packet.len() + 64];
        let len = transport.encrypt(&packet, &mut encrypted)?;

        let pkt = Packet::TransportData(TransportData {
            nonce: 0,
            ciphertext: Bytes::copy_from_slice(&encrypted[..len]),
        });

        let out = pkt.serialize(0);
        sock.send_to(&out, peer)?;
    }
}
