use crate::crypto::noise::NoiseSession;
use std::error::Error;

pub struct SecureTransport {
    noise: NoiseSession,
}

impl SecureTransport {
    pub fn new(noise: NoiseSession) -> Self {
        Self { noise }
    }

    pub fn encrypt(&mut self, plain: &[u8], out: &mut [u8]) -> Result<usize, Box<dyn Error>> {
        Ok(self.noise.encrypt(plain, out)?)
    }

    pub fn decrypt(&mut self, cipher: &[u8], out: &mut [u8]) -> Result<usize, Box<dyn Error>> {
        Ok(self.noise.decrypt(cipher, out)?)
    }
}
