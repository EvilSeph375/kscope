use tun_tap::{Iface, Mode};
use std::io;

pub fn create_tun(name: &str) -> io::Result<Iface> {
    let iface = Iface::new(name, Mode::Tun)?;
    println!("TUN interface {} created", iface.name());
    Ok(iface)
}
