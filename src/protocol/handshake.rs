use crate::crypto::noise::NoiseSession;
use std::error::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HsState {
    Init,
    Sent1,
    Received1,
    Sent2,
    Received2,
    Sent3,
    Complete,
}

pub struct Handshake {
    session: NoiseSession,
    is_initiator: bool,
    state: HsState,
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
            state: HsState::Init,
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
            state: HsState::Init,
        })
    }

    pub fn next_outbound(&mut self, out: &mut [u8]) -> Result<usize, Box<dyn Error>> {
        let n = match (self.is_initiator, self.state) {
            (true, HsState::Init) => {
                self.state = HsState::Sent1;
                self.session.write_handshake(out)?
            }
            (false, HsState::Received1) => {
                self.state = HsState::Sent2;
                self.session.write_handshake(out)?
            }
            (true, HsState::Received2) => {
                self.state = HsState::Sent3;
                self.session.write_handshake(out)?
            }
            _ => 0,
        };
        Ok(n)
    }

    pub fn process_inbound(&mut self, input: &[u8]) -> Result<(), Box<dyn Error>> {
        let mut tmp = [0u8; 1024];
        self.session.read_handshake(input, &mut tmp)?;

        self.state = match (self.is_initiator, self.state) {
            (false, HsState::Init) => HsState::Received1,
            (true, HsState::Sent1) => HsState::Received2,
            (false, HsState::Sent2) => HsState::Complete,
            (true, HsState::Sent3) => HsState::Complete,
            _ => self.state,
        };

        Ok(())
    }

    pub fn is_complete(&self) -> bool {
        matches!(self.state, HsState::Complete)
    }

    pub fn into_session(self) -> NoiseSession {
        self.session
    }
}

