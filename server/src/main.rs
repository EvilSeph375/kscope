use kscope::protocol::handshake::Handshake;
use kscope::net::tun::create_tun;
use kscope::crypto::keyfile::load_keys;
use std::net::UdpSocket;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let _tun = create_tun("kscope0")?;
    println!("Server TUN created");

    let socket = UdpSocket::bind("0.0.0.0:9000")?;
    println!("Server listening on 0.0.0.0:9000");

    let keys = load_keys("keys/server.keys");

    let mut hs = Handshake::new_responder(
        &keys.private,
        &keys.peer_public,
        &keys.psk,
    )?;

    let mut buf = [0u8; 2048];

    let (n, peer) = socket.recv_from(&mut buf)?;
    hs.process_inbound(&buf[..n])?;

    let len = loop {
        let out = hs.next_outbound(&mut buf)?;
        if out > 0 { break out; }
    };
    socket.send_to(&buf[..len], peer)?;

    let (n, _) = socket.recv_from(&mut buf)?;
    hs.process_inbound(&buf[..n])?;

    println!("Handshake complete with {}", peer);
    println!("Now configure interface on BOTH machines:");

    println!("Server:");
    println!("  sudo ip link set kscope0 up");
    println!("  sudo ip addr add 10.0.0.1/24 dev kscope0");

    println!("Client:");
    println!("  sudo ip link set kscope0 up");
    println!("  sudo ip addr add 10.0.0.2/24 dev kscope0");

    println!("After that, we will start transport layer.");

    std::thread::park();
Ok(())
}
