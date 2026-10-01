// Derived from shoes (https://github.com/cfal/shoes), src/anytls/anytls_types.rs,
// commit 60ed3838b346268615c81e4eace4e15e717da23e.
// Copyright (c) 2021-2023 Alex Lau <github@alau.ca>.
// Licensed under the MIT License; see the NOTICE file of this crate.

//! AnyTLS session frames.

use bytes::{BufMut, BytesMut};

/// Frame header size: command (1) + stream id (4) + data length (2).
pub(crate) const HEADER_SIZE: usize = 7;

/// Maximum data length of a single frame.
pub(crate) const MAX_DATA_SIZE: usize = u16::MAX as usize;

/// Frame command.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Command {
    Waste = 0,
    Syn = 1,
    Psh = 2,
    Fin = 3,
    Settings = 4,
    Alert = 5,
    UpdatePaddingScheme = 6,
    SynAck = 7,
    HeartRequest = 8,
    HeartResponse = 9,
    ServerSettings = 10,
}

impl Command {
    pub(crate) fn from_u8(value: u8) -> Option<Self> {
        Some(match value {
            0 => Self::Waste,
            1 => Self::Syn,
            2 => Self::Psh,
            3 => Self::Fin,
            4 => Self::Settings,
            5 => Self::Alert,
            6 => Self::UpdatePaddingScheme,
            7 => Self::SynAck,
            8 => Self::HeartRequest,
            9 => Self::HeartResponse,
            10 => Self::ServerSettings,
            _ => return None,
        })
    }
}

/// Appends a frame to `buf`.
///
/// # Panics
/// Panics if `data` exceeds [`MAX_DATA_SIZE`].
pub(crate) fn encode_frame(buf: &mut BytesMut, cmd: Command, stream_id: u32, data: &[u8]) {
    assert!(data.len() <= MAX_DATA_SIZE, "frame data too long");
    buf.reserve(HEADER_SIZE + data.len());
    buf.put_u8(cmd as u8);
    buf.put_u32(stream_id);
    buf.put_u16(data.len() as u16);
    buf.put_slice(data);
}

/// Appends a [`Command::Waste`] frame carrying `len` zero bytes to `buf`.
pub(crate) fn encode_waste(buf: &mut BytesMut, len: usize) {
    let len = len.min(MAX_DATA_SIZE);
    buf.reserve(HEADER_SIZE + len);
    buf.put_u8(Command::Waste as u8);
    buf.put_u32(0);
    buf.put_u16(len as u16);
    buf.put_bytes(0, len);
}

/// Decodes a frame header into raw command, stream id and data length.
pub(crate) fn decode_header(header: &[u8; HEADER_SIZE]) -> (u8, u32, u16) {
    let stream_id = u32::from_be_bytes([header[1], header[2], header[3], header[4]]);
    let len = u16::from_be_bytes([header[5], header[6]]);
    (header[0], stream_id, len)
}

/// Newline-separated `key=value` pairs used by settings and padding schemes.
///
/// Insertion order is preserved when serializing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct StringMap(Vec<(String, String)>);

impl StringMap {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Inserts or replaces a value.
    pub(crate) fn insert(&mut self, key: impl Into<String>, value: impl Into<String>) {
        let key = key.into();
        let value = value.into();
        match self.0.iter_mut().find(|(k, _)| *k == key) {
            Some((_, v)) => *v = value,
            None => self.0.push((key, value)),
        }
    }

    pub(crate) fn get(&self, key: &str) -> Option<&str> {
        self.0.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Parses lines of the form `key=value`; lines without `=` are ignored.
    pub(crate) fn from_bytes(data: &[u8]) -> Self {
        let mut map = Self::new();
        for line in String::from_utf8_lossy(data).split('\n') {
            let line = line.strip_suffix('\r').unwrap_or(line);
            if let Some((key, value)) = line.split_once('=') {
                map.insert(key, value);
            }
        }
        map
    }

    /// Serializes as `key=value` lines joined by `\n` without a trailing newline.
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        self.0.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("\n").into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_values() {
        for value in 0..=10u8 {
            assert_eq!(Command::from_u8(value).unwrap() as u8, value);
        }
        assert_eq!(Command::from_u8(11), None);
    }

    #[test]
    fn frame_roundtrip() {
        let mut buf = BytesMut::new();
        encode_frame(&mut buf, Command::Psh, 0x01020304, b"hello");
        assert_eq!(buf.len(), HEADER_SIZE + 5);
        let header: [u8; HEADER_SIZE] = buf[..HEADER_SIZE].try_into().unwrap();
        assert_eq!(decode_header(&header), (Command::Psh as u8, 0x01020304, 5));
        assert_eq!(&buf[HEADER_SIZE..], b"hello");
    }

    #[test]
    fn waste_frame() {
        let mut buf = BytesMut::new();
        encode_waste(&mut buf, 30);
        assert_eq!(buf.len(), HEADER_SIZE + 30);
        assert_eq!(&buf[..HEADER_SIZE], &[0, 0, 0, 0, 0, 0, 30]);
        assert!(buf[HEADER_SIZE..].iter().all(|&b| b == 0));
    }

    #[test]
    fn string_map_keeps_order() {
        let mut map = StringMap::new();
        map.insert("v", "2");
        map.insert("client", "test");
        map.insert("padding-md5", "abc");
        assert_eq!(map.to_bytes(), b"v=2\nclient=test\npadding-md5=abc");
        assert_eq!(StringMap::from_bytes(&map.to_bytes()), map);
        assert_eq!(map.get("client"), Some("test"));
        assert_eq!(map.get("missing"), None);
    }
}
