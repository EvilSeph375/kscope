use kscope::crypto::keyfile::load_keys;
use kscope::protocol::{
    handshake::Handshake,
    packet::{Packet, TransportData},
    transport::SecureTransport,
};
use kscope::tun::{TunConfig, TunDevice};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let keys = load_keys("keys/client.keys");

    let mut tun = TunDevice::create(TunConfig {
        name: "kscope0".into(),
        ip: "10.8.0.2".parse()?,
        prefix_len: 24,
        mtu: 1400,
    })?;

    let server = "192.168.137.128:7000";
    let sock = std::net::UdpSocket::bind("0.0.0.0:0")?;

    let mut hs = Handshake::new_initiator(&keys.private, &keys.peer_public, &keys.psk)?;

    let mut buf = [0u8; 2048];

    // === Handshake ===
    let n = hs.next_outbound(&mut buf)?;
    sock.send_to(&buf[..n], server)?;

    while !hs.is_complete() {
        let (n, _) = sock.recv_from(&mut buf)?;
        hs.process_inbound(&buf[..n])?;

        let n = hs.next_outbound(&mut buf)?;
        if n > 0 {
            sock.send_to(&buf[..n], server)?;
        }
    }

    let mut transport = SecureTransport::new(hs.into_session());

    println!("Client: handshake complete");

    // === Data loop ===
    loop {
        let (n, _) = sock.recv_from(&mut buf)?;
        let (pkt, _) = Packet::deserialize(&buf[..n])?;

        if let Packet::TransportData(TransportData { nonce: _, ciphertext }) = pkt {
            let mut plain = vec![0u8; ciphertext.len()];
            let len = transport.decrypt(&ciphertext, &mut plain)?;

            tun.write(&plain[..len])?;
        }
    }
}
