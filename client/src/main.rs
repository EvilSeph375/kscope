use kscope::crypto::noise::NoiseSession;
use kscope::protocol::transport::SecureTransport;
use kscope::tun::create_tun;

use std::error::Error;
use std::net::UdpSocket;

fn main() -> Result<(), Box<dyn Error>> {
    let mut tun = create_tun("kscope0")?;
    println!("Client TUN created");

    let socket = UdpSocket::bind("0.0.0.0:0")?;
    let server = "192.168.137.128:9000";

    println!("Starting handshake...");
    let noise = NoiseSession::client_handshake(&socket, server)?;
    println!("Handshake complete");

    let mut transport = SecureTransport::new(noise);

    let mut net_buf = [0u8; 2048];
    let mut tun_buf = [0u8; 2048];
    let mut crypt_buf = [0u8; 2048];

    loop {
        let n = tun.read(&mut tun_buf)?;
        let enc_len = transport.encrypt_frame(&tun_buf[..n], &mut crypt_buf)?;
        socket.send_to(&crypt_buf[..enc_len], server)?;

        let (len, _) = socket.recv_from(&mut net_buf)?;
        let ip_len = transport.decrypt_frame(&net_buf[..len], &mut tun_buf)?;
        tun.write(&tun_buf[..ip_len])?;
    }
}
