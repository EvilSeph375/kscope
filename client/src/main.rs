use kscope::protocol::handshake::Handshake;
use kscope::protocol::transport::SecureTransport;
use kscope::tun::device::{TunDevice, TunConfig};
use std::net::UdpSocket;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let server = "192.168.137.128:9000";

    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect(server)?;

    println!("Starting handshake...");

    let static_private = [1u8; 32];
    let remote_static  = [2u8; 32];
    let psk = [3u8; 32];

    let mut hs = Handshake::new_initiator(&static_private, &remote_static, &psk)?;

    let mut out = [0u8; 1024];
    let n = hs.next_outbound(&mut out)?;
    socket.send(&out[..n])?;

    let mut buf = [0u8; 1024];
    let n = socket.recv(&mut buf)?;
    hs.process_inbound(&buf[..n])?;

    let noise = hs.into_session();
    let mut transport = SecureTransport::new(noise);

    println!("Handshake completed");

    let tun = TunDevice::create(TunConfig::default())?;
    println!("VPN is up");

    loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}
