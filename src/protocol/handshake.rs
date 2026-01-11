use crate::crypto::noise::NoiseSession;
use std::error::Error;

pub struct Handshake {
    session: NoiseSession,
    is_initiator: bool,
    complete: bool,
}

impl Handshake {
    pub fn new_initiator(privk: &[u8], pubk: &[u8], psk: &[u8]) -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            session: NoiseSession::new_initiator(privk, pubk, psk)?,
            is_initiator: true,
            complete: false,
        })
    }

    pub fn new_responder(privk: &[u8], pubk: &[u8], psk: &[u8]) -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            session: NoiseSession::new_responder(privk, pubk, psk)?,
            is_initiator: false,
            complete: false,
        })
    }

    pub fn next_outbound(&mut self, out: &mut [u8]) -> Result<usize, Box<dyn Error>> {
        if self.complete {
            return Ok(0);
        }

        let n = self.session.write_handshake(out)?;

        if !self.is_initiator {
            self.complete = true;
        }

        Ok(n)
    }

    pub fn process_inbound(&mut self, input: &[u8]) -> Result<(), Box<dyn Error>> {
        let mut tmp = [0u8; 1024];
        self.session.read_handshake(input, &mut tmp)?;

        if self.is_initiator {
            self.complete = true;
        }

        Ok(())
    }

    pub fn is_complete(&self) -> bool {
        self.complete
    }

    pub fn into_session(self) -> NoiseSession {
        self.session
    }
}
