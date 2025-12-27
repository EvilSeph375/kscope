use kscope::net::tun::create_tun;
use std::thread;
use std::time::Duration;

fn main() {
    let _tun = create_tun("kscope0").expect("TUN create failed");
    println!("TUN created, sleeping...");
    loop {
        thread::sleep(Duration::from_secs(10));
    }
}
