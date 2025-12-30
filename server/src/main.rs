use kscope::protocol::handshake::Handshake;
use kscope::net::tun::create_tun;
use kscope::crypto::keyfile::load_keys;
use std::net::UdpSocket;
use std::error::Error;
use kscope::protocol::transport::SecureTransport;
use std::thread;

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
let mut transport = SecureTransport::new(hs.into_session());

let tun_fd = _tun.as_raw_fd();
let udp = socket.try_clone()?;

thread::spawn(move || {
    let mut tun_buf = [0u8; 2000];
    let mut out = [0u8; 2048];

    loop {
        let n = nix::unistd::read(tun_fd, &mut tun_buf).unwrap();
        let len = transport.encrypt(&tun_buf[..n], &mut out).unwrap();
        udp.send_to(&out[..len], peer).unwrap();
    }
});

let mut in_buf = [0u8; 2048];
let mut plain = [0u8; 2000];

loop {
    let (n, _) = socket.recv_from(&mut in_buf)?;
    let len = transport.decrypt(&in_buf[..n], &mut plain)?;
    nix::unistd::write(tun_fd, &plain[..len]).unwrap();
}

    Ok(())
}
