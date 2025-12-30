use kscope::protocol::handshake::Handshake;
use kscope::net::tun::create_tun;
use kscope::crypto::keyfile::load_keys;
use std::net::UdpSocket;
use std::error::Error;
use kscope::protocol::transport::SecureTransport;
use std::thread;

fn main() -> Result<(), Box<dyn Error>> {
    let _tun = create_tun("kscope0")?;
    println!("Client TUN created");

    let server = "192.168.38.127:9000";
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect(server)?;

    let keys = load_keys("keys/client.keys");

    let mut hs = Handshake::new_initiator(
        &keys.private,
        &keys.peer_public,
        &keys.psk,
    )?;

    println!("Starting handshake...");

    let mut buf = [0u8; 2048];

    let len = loop {
        let n = hs.next_outbound(&mut buf)?;
        if n > 0 { break n; }
    };
    socket.send(&buf[..len])?;

    let n = socket.recv(&mut buf)?;
    hs.process_inbound(&buf[..n])?;

    let len = loop {
        let out = hs.next_outbound(&mut buf)?;
        if out > 0 { break out; }
    };
    socket.send(&buf[..len])?;

    println!("Handshake complete.");
let mut transport = SecureTransport::new(hs.into_session());

let tun_fd = _tun.as_raw_fd();
let udp = socket.try_clone()?;

thread::spawn(move || {
    let mut tun_buf = [0u8; 2000];
    let mut out = [0u8; 2048];

    loop {
        let n = nix::unistd::read(tun_fd, &mut tun_buf).unwrap();
        let len = transport.encrypt(&tun_buf[..n], &mut out).unwrap();
        udp.send(&out[..len]).unwrap();
    }
});

let mut in_buf = [0u8; 2048];
let mut plain = [0u8; 2000];

loop {
    let n = socket.recv(&mut in_buf)?;
    let len = transport.decrypt(&in_buf[..n], &mut plain)?;
    nix::unistd::write(tun_fd, &plain[..len]).unwrap();
}

    Ok(())
}
