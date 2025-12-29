use std::fs;

pub struct LoadedKeys {
    pub private: Vec<u8>,
    pub peer_public: Vec<u8>,
    pub psk: Vec<u8>,
}

pub fn load_keys(path: &str) -> LoadedKeys {
    let text = fs::read_to_string(path).expect("key file");

    let mut private = None;
    let mut peer_public = None;
    let mut psk = None;

    for line in text.lines() {
        let (k, v) = line.split_once('=').unwrap();
        match k {
            "PRIVATE" => private = Some(base64::decode(v).unwrap()),
            "PEER_PUBLIC" => peer_public = Some(base64::decode(v).unwrap()),
            "PSK" => psk = Some(base64::decode(v).unwrap()),
            _ => {}
        }
    }

    LoadedKeys {
        private: private.unwrap(),
        peer_public: peer_public.unwrap(),
        psk: psk.unwrap(),
    }
}
