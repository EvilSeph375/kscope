use kscope::protocol::handshake::Handshake;
use kscope::protocol::transport::SecureTransport;
use std::net::UdpSocket;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let server_addr = "127.0.0.1:9000";

    let client_static = [1u8; 32];
    let server_static = [2u8; 32];
    let psk = [9u8; 32];

    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect(server_addr)?;

    let mut handshake = Handshake::new_initiator(&client_static, &server_static, &psk)?;

    let mut buf = [0u8; 2048];

    // === Proper IKpsk2 handshake loop ===
    while !handshake.is_complete() {
        let out_len = handshake.next_outbound(&mut buf)?;
        if out_len > 0 {
            socket.send(&buf[..out_len])?;
        }

        if handshake.is_complete() {
            break;
        }

        let recv_len = socket.recv(&mut buf)?;
        handshake.process_inbound(&buf[..recv_len])?;
    }

    let session = handshake.into_session();
    let mut transport = SecureTransport::new(session);

    println!("Secure tunnel established.");

    // === Encrypted transport ===
    let msg = b"Hello through encrypted tunnel!";
    let mut enc = [0u8; 2048];
    let len = transport.encrypt_frame(msg, &mut enc)?;
    socket.send(&enc[..len])?;

    let recv_len = socket.recv(&mut buf)?;
    let mut out = [0u8; 2048];
    let len = transport.decrypt_frame(&buf[..recv_len], &mut out)?;

    println!("Received: {}", String::from_utf8_lossy(&out[..len]));

    Ok(())
}
