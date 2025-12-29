use kscope::protocol::handshake::Handshake;
use kscope::protocol::transport::SecureTransport;
use kscope::tun::device::{TunDevice, TunConfig};
use std::net::UdpSocket;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let socket = UdpSocket::bind("0.0.0.0:9000")?;

    println!("Server listening on 0.0.0.0:9000");
    println!("Waiting for client handshake...");

    let static_private = [2u8; 32];
    let remote_static  = [1u8; 32];
    let psk = [3u8; 32];

    let mut buf = [0u8; 1024];
    let (n, peer) = socket.recv_from(&mut buf)?;

    let mut hs = Handshake::new_responder(&static_private, &remote_static, &psk)?;
    hs.process_inbound(&buf[..n])?;

    let mut out = [0u8; 1024];
    let n = hs.next_outbound(&mut out)?;
    socket.send_to(&out[..n], peer)?;

    let noise = hs.into_session();
    let mut transport = SecureTransport::new(noise);

    println!("Handshake completed with {}", peer);

    let tun = TunDevice::create(TunConfig::default())?;
    println!("VPN is up");

    loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}
