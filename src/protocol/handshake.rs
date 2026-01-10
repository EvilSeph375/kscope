use crate::crypto::noise::NoiseSession;
use crate::protocol::packet::{Packet, HandshakeInit, HandshakeResponse};
use std::error::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HsState {
    Init,
    Sent1,
    Received1,
    Sent2,
    Complete,
}

pub struct Handshake {
    session: NoiseSession,
    is_initiator: bool,
    state: HsState,
}

impl Handshake {
    pub fn new_initiator(static_private: &[u8], remote_static: &[u8], psk: &[u8]) -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            session: NoiseSession::new_initiator(static_private, remote_static, psk)?,
            is_initiator: true,
            state: HsState::Init,
        })
    }

    pub fn new_responder(static_private: &[u8], remote_static: &[u8], psk: &[u8]) -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            session: NoiseSession::new_responder(static_private, remote_static, psk)?,
            is_initiator: false,
            state: HsState::Init,
        })
    }

    pub fn next_outbound(&mut self) -> Result<Option<Packet>, Box<dyn Error>> {
        let mut buf = [0u8; 1024];

        let pkt = match (self.is_initiator, self.state) {
            (true, HsState::Init) => {
                let n = self.session.write_handshake(&mut buf)?;
                self.state = HsState::Sent1;
                Some(Packet::HandshakeInit(HandshakeInit::deserialize(&buf[..n])?))
            }
            (false, HsState::Received1) => {
                let n = self.session.write_handshake(&mut buf)?;
                self.state = HsState::Sent2;
                Some(Packet::HandshakeResponse(HandshakeResponse::deserialize(&buf[..n])?))
            }
            _ => None,
        };

        Ok(pkt)
    }

    pub fn process_inbound(&mut self, pkt: Packet) -> Result<(), Box<dyn Error>> {
        let mut out = [0u8; 1024];

        match pkt {
            Packet::HandshakeInit(p) => {
                self.session.read_handshake(&p.serialize(), &mut out)?;
                self.state = HsState::Received1;
            }
            Packet::HandshakeResponse(p) => {
                self.session.read_handshake(&p.serialize(), &mut out)?;
                self.state = HsState::Complete;
            }
            _ => {}
        }

        Ok(())
    }

    pub fn is_complete(&self) -> bool {
        self.state == HsState::Complete
    }

    pub fn into_session(self) -> NoiseSession {
        self.session
    }
}
