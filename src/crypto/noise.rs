use snow::{Builder, HandshakeState, TransportState};
use std::error::Error;

const NOISE_PARAMS: &str = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";

pub struct NoiseSession {
    handshake: Option<HandshakeState>,
    transport: Option<TransportState>,
}

impl NoiseSession {
    pub fn new_initiator(
        static_private: &[u8],
        remote_static: &[u8],
        psk: &[u8],
    ) -> Result<Self, Box<dyn Error>> {
        let builder = Builder::new(NOISE_PARAMS.parse()?);

        let handshake = builder
            .local_private_key(static_private)
            .remote_public_key(remote_static)
            .psk(2, psk)
            .build_initiator()?;

        Ok(Self { handshake: Some(handshake), transport: None })
    }

    pub fn new_responder(
        static_private: &[u8],
        psk: &[u8],
    ) -> Result<Self, Box<dyn Error>> {
        let builder = Builder::new(NOISE_PARAMS.parse()?);

        let handshake = builder
            .local_private_key(static_private)
            .psk(2, psk)
            .build_responder()?;

        Ok(Self { handshake: Some(handshake), transport: None })
    }

    fn finish_if_complete(&mut self) -> Result<(), Box<dyn Error>> {
        if let Some(hs) = self.handshake.as_ref() {
            if hs.is_handshake_finished() {
                let hs = self.handshake.take().unwrap();
                self.transport = Some(hs.into_transport_mode()?);
            }
        }
        Ok(())
    }

    pub fn write_handshake(&mut self, out: &mut [u8]) -> Result<usize, Box<dyn Error>> {
        let len = self.handshake.as_mut().unwrap().write_message(&[], out)?;
        self.finish_if_complete()?;
        Ok(len)
    }

    pub fn read_handshake(&mut self, input: &[u8], out: &mut [u8]) -> Result<(), Box<dyn Error>> {
        self.handshake.as_mut().unwrap().read_message(input, out)?;
        self.finish_if_complete()?;
        Ok(())
    }

    pub fn encrypt(&mut self, plaintext: &[u8], out: &mut [u8]) -> Result<usize, Box<dyn Error>> {
        Ok(self.transport.as_mut().unwrap().write_message(plaintext, out)?)
    }

    pub fn decrypt(&mut self, input: &[u8], out: &mut [u8]) -> Result<usize, Box<dyn Error>> {
        Ok(self.transport.as_mut().unwrap().read_message(input, out)?)
    }

    pub fn is_ready(&self) -> bool {
        self.transport.is_some()
    }
}
