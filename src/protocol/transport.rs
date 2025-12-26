use crate::crypto::noise::NoiseSession;
use std::error::Error;

const MAX_PACKET: usize = 1500;

pub struct SecureTransport {
    noise: NoiseSession,
}

impl SecureTransport {
    pub fn new(noise: NoiseSession) -> Self {
        Self { noise }
    }

    pub fn encrypt_frame(
        &mut self,
        payload: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Box<dyn Error>> {
        let len = self.noise.encrypt(payload, out)?;
        Ok(len)
    }

    pub fn decrypt_frame(
        &mut self,
        input: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Box<dyn Error>> {
        let len = self.noise.decrypt(input, out)?;
        Ok(len)
    }
}
