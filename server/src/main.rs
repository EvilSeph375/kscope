use kscope::protocol::handshake::Handshake;
use kscope::protocol::transport::SecureTransport;
use kscope::net::tun::create_tun;

use std::net::UdpSocket;
use std::error::Error;
use std::sync::{Arc, Mutex};
use std::thread;

fn main() -> Result<(), Box<dyn Error>> {

    let tun = Arc::new(create_tun("kscope0")?);
    println!("TUN interface kscope0 created");

    let socket = UdpSocket::bind("0.0.0.0:9000")?;
    println!("Server listening on 0.0.0.0:9000");

    let server_static = [2u8; 32];
    let client_static = [1u8; 32];
    let psk = [9u8; 32];

    let mut buf = [0u8; 2048];
    let (len, peer) = socket.recv_from(&mut buf)?;

    let mut handshake = Handshake::new_responder(&server_static, &client_static, &psk)?;
    handshake.process_inbound(&buf[..len])?;

    let out = handshake.next_outbound(&mut buf)?;
    socket.send_to(&buf[..out], peer)?;

    let (len, _) = socket.recv_from(&mut buf)?;
    handshake.process_inbound(&buf[..len])?;

    let session = handshake.into_session();
    let transport = Arc::new(Mutex::new(SecureTransport::new(session)));

    println!("Secure tunnel established.");

    let udp = Arc::new(socket);

    // === Thread A: TUN → UDP ===
    {
        let tun = tun.clone();
        let udp = udp.clone();
        let transport = transport.clone();

        thread::spawn(move || {
            let mut tun_buf = [0u8; 1500];
            let mut net_buf = [0u8; 2048];

            loop {
                let len = tun.recv(&mut tun_buf).unwrap();
                let enc = transport.lock().unwrap()
                    .encrypt_frame(&tun_buf[..len], &mut net_buf).unwrap();
                udp.send_to(&net_buf[..enc], peer).unwrap();
            }
        });
    }

    // === Thread B: UDP → TUN ===
    {
        let tun = tun.clone();
        let udp = udp.clone();
        let transport = transport.clone();

        thread::spawn(move || {
            let mut net_buf = [0u8; 2048];
            let mut tun_buf = [0u8; 1500];

            loop {
                let (len, _) = udp.recv_from(&mut net_buf).unwrap();
                let dec = transport.lock().unwrap()
                    .decrypt_frame(&net_buf[..len], &mut tun_buf).unwrap();
                tun.send(&tun_buf[..dec]).unwrap();
            }
        });
    }

    loop { thread::park(); }
}
