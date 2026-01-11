use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::convert::TryInto;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    HandshakeInit = 0x01,
    HandshakeResponse = 0x02,
    TransportData = 0x03,
    KeepAlive = 0x04,
    ErrorPacket = 0xFF,
}

impl TryFrom<u8> for PacketType {
    type Error = String;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value {
            0x01 => PacketType::HandshakeInit,
            0x02 => PacketType::HandshakeResponse,
            0x03 => PacketType::TransportData,
            0x04 => PacketType::KeepAlive,
            0xFF => PacketType::ErrorPacket,
            _ => return Err(format!("Invalid packet type: {}", value)),
        })
    }
}

#[derive(Debug, Clone)]
pub struct PacketHeader {
    pub version: u8,
    pub packet_type: PacketType,
    pub data_len: u16,
    pub session_id: u32,
}

impl PacketHeader {
    pub const SIZE: usize = 8;

    pub fn new(packet_type: PacketType, data_len: u16, session_id: u32) -> Self {
        Self { version: 0x01, packet_type, data_len, session_id }
    }

    pub fn serialize(&self) -> [u8; 8] {
        let mut b = [0u8; 8];
        b[0] = self.version;
        b[1] = self.packet_type as u8;
        b[2..4].copy_from_slice(&self.data_len.to_be_bytes());
        b[4..8].copy_from_slice(&self.session_id.to_be_bytes());
        b
    }

    pub fn deserialize(d: &[u8]) -> crate::Result<Self> {
        if d.len() < 8 { return Err(crate::KScopeError::Protocol("Header too small".into())); }
        Ok(Self {
            version: d[0],
            packet_type: PacketType::try_from(d[1]).map_err(crate::KScopeError::Protocol)?,
            data_len: u16::from_be_bytes([d[2], d[3]]),
            session_id: u32::from_be_bytes([d[4], d[5], d[6], d[7]]),
        })
    }
}

#[derive(Debug, Clone)]
pub struct HandshakeInit { pub payload: Bytes }
#[derive(Debug, Clone)]
pub struct HandshakeResponse { pub payload: Bytes }

#[derive(Debug, Clone)]
pub struct TransportData { pub nonce: u64, pub ciphertext: Bytes }

#[derive(Debug, Clone)]
pub struct KeepAlive { pub timestamp: u64, pub random_data: [u8; 16] }

#[derive(Debug, Clone)]
pub struct ErrorPacket { pub code: u16, pub message: String }

#[derive(Debug, Clone)]
pub enum Packet {
    HandshakeInit(HandshakeInit),
    HandshakeResponse(HandshakeResponse),
    TransportData(TransportData),
    KeepAlive(KeepAlive),
    Error(ErrorPacket),
}

impl Packet {
    pub fn packet_type(&self) -> PacketType {
        match self {
            Packet::HandshakeInit(_) => PacketType::HandshakeInit,
            Packet::HandshakeResponse(_) => PacketType::HandshakeResponse,
            Packet::TransportData(_) => PacketType::TransportData,
            Packet::KeepAlive(_) => PacketType::KeepAlive,
            Packet::Error(_) => PacketType::ErrorPacket,
        }
    }

    pub fn serialize(&self, session_id: u32) -> Bytes {
        let data = match self {
            Packet::HandshakeInit(p) => p.payload.clone(),
            Packet::HandshakeResponse(p) => p.payload.clone(),
            Packet::TransportData(p) => {
                let mut b = BytesMut::with_capacity(8 + p.ciphertext.len());
                b.put_u64(p.nonce);
                b.extend_from_slice(&p.ciphertext);
                b.freeze()
            }
            Packet::KeepAlive(_) => Bytes::new(),
            Packet::Error(p) => {
                let mut b = BytesMut::new();
                b.put_u16(p.code);
                b.extend_from_slice(p.message.as_bytes());
                b.freeze()
            }
        };

        let h = PacketHeader::new(self.packet_type(), data.len() as u16, session_id);
        let mut out = BytesMut::with_capacity(8 + data.len());
        out.extend_from_slice(&h.serialize());
        out.extend_from_slice(&data);
        out.freeze()
    }

    pub fn deserialize(buf: &[u8]) -> crate::Result<(Packet, u32)> {
        let h = PacketHeader::deserialize(buf)?;
        let data = &buf[8..8 + h.data_len as usize];

        let pkt = match h.packet_type {
            PacketType::HandshakeInit => Packet::HandshakeInit(HandshakeInit { payload: Bytes::copy_from_slice(data) }),
            PacketType::HandshakeResponse => Packet::HandshakeResponse(HandshakeResponse { payload: Bytes::copy_from_slice(data) }),
            PacketType::TransportData => {
                let mut d = Bytes::copy_from_slice(data);
                let nonce = d.get_u64();
                Packet::TransportData(TransportData { nonce, ciphertext: d })
            }
            PacketType::KeepAlive => Packet::KeepAlive(KeepAlive { timestamp: 0, random_data: [0; 16] }),
            PacketType::ErrorPacket => Packet::Error(ErrorPacket { code: 0, message: String::new() }),
        };

        Ok((pkt, h.session_id))
    }
}
