// Derived from shoes (https://github.com/cfal/shoes), src/anytls/anytls_padding.rs,
// commit 60ed3838b346268615c81e4eace4e15e717da23e.
// Copyright (c) 2021-2023 Alex Lau <github@alau.ca>.
// Licensed under the MIT License; see the NOTICE file of this crate.

//! AnyTLS padding schemes.

use md5::{Digest, Md5};
use std::sync::{Arc, RwLock};

use crate::frame::StringMap;

/// Marker in generated sizes: stop if no payload remains, otherwise continue.
pub(crate) const CHECK_MARK: i32 = -1;

/// Default padding scheme of the AnyTLS reference implementation (anytls-go).
///
/// Its MD5 digest is `75cff2ad89aadf5e257059ee571ebe11`.
pub const DEFAULT_PADDING_SCHEME: &[u8] = b"stop=8
0=30-30
1=100-400
2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000
3=9-9,500-1000
4=500-1000
5=500-1000
6=500-1000
7=500-1000";

/// A parsed padding scheme.
#[derive(Debug)]
pub(crate) struct PaddingScheme {
    map: StringMap,
    stop: u32,
    md5: String,
}

impl PaddingScheme {
    /// Parses a raw padding scheme.
    ///
    /// Returns `None` if the scheme is empty or has no valid `stop` entry.
    pub(crate) fn parse(raw: &[u8]) -> Option<Self> {
        let map = StringMap::from_bytes(raw);
        if map.is_empty() {
            return None;
        }
        let stop = map.get("stop")?.trim().parse().ok()?;
        let md5 = Md5::digest(raw).iter().map(|b| format!("{b:02x}")).collect();
        Some(Self { map, stop, md5 })
    }

    /// Lowercase hex MD5 of the raw scheme bytes.
    pub(crate) fn md5(&self) -> &str {
        &self.md5
    }

    /// Packets with a number below this value are padded.
    pub(crate) fn stop(&self) -> u32 {
        self.stop
    }

    /// Record payload sizes for packet number `pkt`.
    ///
    /// [`CHECK_MARK`] entries mean "stop if no payload remains".
    /// Random sizes are drawn from `[min, max)`, like anytls-go.
    pub(crate) fn sizes(&self, pkt: u32) -> Vec<i32> {
        let Some(spec) = self.map.get(&pkt.to_string()) else { return Vec::new() };

        let mut sizes = Vec::new();
        for part in spec.split(',') {
            let part = part.trim();
            if part == "c" {
                sizes.push(CHECK_MARK);
                continue;
            }

            let Some((min, max)) = part.split_once('-') else { continue };
            let (Ok(min), Ok(max)) = (min.trim().parse::<i64>(), max.trim().parse::<i64>()) else { continue };
            let (min, max) = (min.min(max), min.max(max));
            if min <= 0 || max <= 0 {
                continue;
            }

            let size = if min == max { min } else { rand::random_range(min..max) };
            sizes.push(size.min(i32::MAX as i64) as i32);
        }
        sizes
    }
}

impl Default for PaddingScheme {
    fn default() -> Self {
        Self::parse(DEFAULT_PADDING_SCHEME).expect("default padding scheme is valid")
    }
}

/// Padding scheme shared by all sessions to one server address.
///
/// New sessions take a snapshot when they are created.
#[derive(Debug)]
pub(crate) struct PaddingSlot(RwLock<Arc<PaddingScheme>>);

impl PaddingSlot {
    pub(crate) fn new(scheme: Arc<PaddingScheme>) -> Self {
        Self(RwLock::new(scheme))
    }

    pub(crate) fn load(&self) -> Arc<PaddingScheme> {
        self.0.read().unwrap().clone()
    }

    pub(crate) fn store(&self, scheme: Arc<PaddingScheme>) {
        *self.0.write().unwrap() = scheme;
    }
}

impl Default for PaddingSlot {
    fn default() -> Self {
        Self::new(Arc::new(PaddingScheme::default()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_scheme_matches_reference() {
        let scheme = PaddingScheme::default();
        assert_eq!(DEFAULT_PADDING_SCHEME.len(), 137);
        assert_eq!(scheme.md5(), "75cff2ad89aadf5e257059ee571ebe11");
        assert_eq!(scheme.stop(), 8);
        assert_eq!(scheme.sizes(0), vec![30]);
        assert!(scheme.sizes(8).is_empty());
    }

    #[test]
    fn random_range_excludes_max() {
        let scheme = PaddingScheme::parse(b"stop=2\n1=10-12").unwrap();
        for _ in 0..1000 {
            let sizes = scheme.sizes(1);
            assert_eq!(sizes.len(), 1);
            assert!((10..12).contains(&sizes[0]), "size {} out of range", sizes[0]);
        }
    }

    #[test]
    fn check_mark_and_swapped_range() {
        let scheme = PaddingScheme::parse(b"stop=3\n2=500-400,c,7-7,0-5").unwrap();
        let sizes = scheme.sizes(2);
        assert_eq!(sizes.len(), 3);
        assert!((400..500).contains(&sizes[0]));
        assert_eq!(sizes[1], CHECK_MARK);
        assert_eq!(sizes[2], 7);
    }

    #[test]
    fn invalid_schemes() {
        assert!(PaddingScheme::parse(b"").is_none());
        assert!(PaddingScheme::parse(b"0=30-30").is_none());
        assert!(PaddingScheme::parse(b"stop=x\n0=30-30").is_none());
    }

    #[test]
    fn slot_replaces_scheme() {
        let slot = PaddingSlot::default();
        let old = slot.load();
        slot.store(Arc::new(PaddingScheme::parse(b"stop=1\n0=5-5").unwrap()));
        assert_eq!(old.md5(), "75cff2ad89aadf5e257059ee571ebe11");
        assert_ne!(slot.load().md5(), old.md5());
    }
}
