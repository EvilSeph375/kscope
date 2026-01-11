use std::net::UdpSocket;
use kscope::crypto::keyfile::load_keys;
use kscope::protocol::handshake::Handshake;
use kscope::protocol::packet::{Packet, TransportData};
use kscope::protocol::transport::SecureTransport;
use kscope::tun::{TunConfig, TunDevice};
use bytes::Bytes;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

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
    let mut buf = [0u8; 2048];

    let n = hs.next_outbound(&mut buf)?;
    sock.send_to(&buf[..n], server)?;

    loop {
        let (n, _) = sock.recv_from(&mut buf)?;
        hs.process_inbound(&buf[..n])?;

        let out = hs.next_outbound(&mut buf)?;
        if out > 0 {
            sock.send_to(&buf[..out], server)?;
        }

        if hs.is_complete() {
            break;
        }
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
