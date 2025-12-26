use rand_core::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

pub struct KeyPair {
    pub private: StaticSecret,
    pub public: PublicKey,
}

impl KeyPair {
    pub fn generate() -> Self {
        let private = StaticSecret::new(OsRng);
        let public = PublicKey::from(&private);
        Self { private, public }
    }
}
