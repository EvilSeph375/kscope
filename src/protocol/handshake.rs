use crate::crypto::noise::NoiseSession;
use std::error::Error;

pub struct Handshake {
    session: NoiseSession,
    is_initiator: bool,
    step: u8,
}

impl Handshake {
    pub fn new_initiator(
        static_private: &[u8],
        remote_static: &[u8],
        psk: &[u8],
    ) -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            session: NoiseSession::new_initiator(static_private, remote_static, psk)?,
            is_initiator: true,
            step: 0,
        })
    }

    pub fn new_responder(
        static_private: &[u8],
        remote_static: &[u8],
        psk: &[u8],
    ) -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            session: NoiseSession::new_responder(static_private, remote_static, psk)?,
            is_initiator: false,
            step: 0,
        })
    }

    pub fn is_complete(&self) -> bool {
        self.session.is_ready()
    }

    pub fn next_outbound(&mut self, out: &mut [u8]) -> Result<usize, Box<dyn Error>> {
        if self.is_complete() {
            return Ok(0);
        }

        // Client sends first and third
        if self.is_initiator && (self.step == 0 || self.step == 2) {
            let n = self.session.write_handshake(out)?;
            self.step += 1;
            return Ok(n);
        }

        // Server sends second
        if !self.is_initiator && self.step == 1 {
            let n = self.session.write_handshake(out)?;
            self.step += 1;
            return Ok(n);
        }

        Ok(0)
    }

    pub fn process_inbound(&mut self, input: &[u8]) -> Result<(), Box<dyn Error>> {
        let mut tmp = [0u8; 1024];
        self.session.read_handshake(input, &mut tmp)?;
        self.step += 1;
        Ok(())
    }

    pub fn into_session(self) -> NoiseSession {
        self.session
    }
}
