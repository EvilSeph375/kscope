use crate::crypto::noise::NoiseSession;
use std::error::Error;

pub struct Handshake {
    session: NoiseSession,
}

impl Handshake {
    pub fn new_initiator(
        static_private: &[u8],
        remote_static: &[u8],
        psk: &[u8],
    ) -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            session: NoiseSession::new_initiator(static_private, remote_static, psk)?,
        })
    }

    pub fn new_responder(
        static_private: &[u8],
        psk: &[u8],
    ) -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            session: NoiseSession::new_responder(static_private, psk)?,
        })
    }

    pub fn is_complete(&self) -> bool {
        self.session.is_ready()
    }

    pub fn next_outbound(&mut self, out: &mut [u8]) -> Result<usize, Box<dyn Error>> {
        if self.is_complete() {
            return Ok(0);
        }
        self.session.write_handshake(out)
    }

    pub fn process_inbound(&mut self, input: &[u8]) -> Result<(), Box<dyn Error>> {
        let mut tmp = vec![0u8; 1024];
        self.session.read_handshake(input, &mut tmp)?;
        Ok(())
    }

    pub fn into_session(self) -> NoiseSession {
        self.session
    }
}
