fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let keys = load_keys("keys/client.keys");
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
            println!("Client: handshake complete");
            break;
        }
    }

    Ok(())
}
