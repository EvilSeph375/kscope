use crate::crypto::noise::NoiseSession;
use std::error::Error;

pub struct Handshake {
    session: NoiseSession,
}

impl Handshake {
    pub fn new_initiator(privk: &[u8], pubk: &[u8], psk: &[u8]) -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            session: NoiseSession::new_initiator(privk, pubk, psk)?,
        })
    }

    pub fn new_responder(privk: &[u8], pubk: &[u8], psk: &[u8]) -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            session: NoiseSession::new_responder(privk, pubk, psk)?,
        })
    }

    pub fn next_outbound(&mut self, out: &mut [u8]) -> Result<usize, Box<dyn Error>> {
        if self.session.is_ready() {
            return Ok(0);
        }
        Ok(self.session.write_handshake(out)?)
    }

    pub fn process_inbound(&mut self, input: &[u8]) -> Result<(), Box<dyn Error>> {
        let mut tmp = [0u8; 1024];
        self.session.read_handshake(input, &mut tmp)?;
        Ok(())
    }

    pub fn is_complete(&self) -> bool {
        self.session.is_ready()
    }

    pub fn into_session(self) -> NoiseSession {
        self.session
    }
}
