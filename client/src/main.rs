use kscope::protocol::handshake::Handshake;
use kscope::protocol::transport::SecureTransport;
use kscope::net::tun::create_tun;

use std::net::UdpSocket;
use std::error::Error;
use std::sync::{Arc, Mutex};
use std::thread;

fn main() -> Result<(), Box<dyn Error>> {

    let server_addr = "192.168.137.128:9000";

    let client_static = [1u8; 32];
    let server_static = [2u8; 32];
    let psk = [9u8; 32];

    // === UDP + Handshake ===
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect(server_addr)?;

    let mut handshake = Handshake::new_initiator(&client_static, &server_static, &psk)?;
    let mut buf = [0u8; 2048];

    while !handshake.is_complete() {
        let out_len = handshake.next_outbound(&mut buf)?;
        if out_len > 0 {
            socket.send(&buf[..out_len])?;
        }

        if handshake.is_complete() { break; }

        let recv_len = socket.recv(&mut buf)?;
        handshake.process_inbound(&buf[..recv_len])?;
    }

    let session = handshake.into_session();
    let transport = Arc::new(Mutex::new(SecureTransport::new(session)));

    println!("Secure tunnel established.");

    // === Create TUN BEFORE data loop ===
    let tun = Arc::new(create_tun("kscope0")?);
    println!("Client TUN ready.");

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
                udp.send(&net_buf[..enc]).unwrap();
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
                let len = udp.recv(&mut net_buf).unwrap();
                let dec = transport.lock().unwrap()
                    .decrypt_frame(&net_buf[..len], &mut tun_buf).unwrap();
                tun.send(&tun_buf[..dec]).unwrap();
            }
        });
    }

    loop { thread::park(); }
}
