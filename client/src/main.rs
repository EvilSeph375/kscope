use kscope::net::tun::create_tun;
use kscope::protocol::handshake::Handshake;
use std::net::UdpSocket;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let _tun = create_tun("kscope0")?;
    println!("TUN interface kscope0 created");
    println!("Client TUN created");

    let server = "192.168.38.127:9000";
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect(server)?;

    let mut hs = Handshake::new_initiator()?;
    let mut buf = [0u8; 2048];

    println!("Starting handshake...");

    let len = hs.next_outbound(&mut buf)?;
    socket.send(&buf[..len])?;

    let n = socket.recv(&mut buf)?;
    hs.process_inbound(&buf[..n])?;

    // 🔧 КЛЮЧЕВОЕ ИСПРАВЛЕНИЕ
    let len = loop {
        let out = hs.next_outbound(&mut buf)?;
        if out > 0 {
            break out;
        }
    };

    socket.send(&buf[..len])?;

    println!("Handshake complete.");

    Ok(())
}
