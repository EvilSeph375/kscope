use kscope::protocol::handshake::Handshake;
use kscope::protocol::transport::SecureTransport;
use std::net::UdpSocket;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let addr = "0.0.0.0:9000";

    let server_static = [2u8; 32];
    let psk = [9u8; 32];

    let socket = UdpSocket::bind(addr)?;
    println!("Server listening on {}", addr);

    let mut buf = [0u8; 2048];

    let mut peer = None;
    let client_static = [1u8; 32];   // тот же, что и на клиенте
    let mut handshake = Handshake::new_responder(&server_static, &client_static, &psk)?;


    // === Proper IKpsk2 handshake loop ===
    while !handshake.is_complete() {
        let (len, p) = socket.recv_from(&mut buf)?;
        peer = Some(p);

        handshake.process_inbound(&buf[..len])?;

        if !handshake.is_complete() {
            let out_len = handshake.next_outbound(&mut buf)?;
            if out_len > 0 {
                socket.send_to(&buf[..out_len], p)?;
            }
        }
    }

    let peer = peer.unwrap();
    let session = handshake.into_session();
    let mut transport = SecureTransport::new(session);

    println!("Secure tunnel established.");

    // === Encrypted transport ===
    let (recv_len, _) = socket.recv_from(&mut buf)?;
    let mut out = [0u8; 2048];
    let len = transport.decrypt_frame(&buf[..recv_len], &mut out)?;
    println!("Received: {}", String::from_utf8_lossy(&out[..len]));

    let reply = b"Hello from secure server!";
    let mut enc = [0u8; 2048];
    let len = transport.encrypt_frame(reply, &mut enc)?;
    socket.send_to(&enc[..len], peer)?;

    Ok(())
}
