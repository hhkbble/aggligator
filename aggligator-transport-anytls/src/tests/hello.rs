//! Compares our ClientHello with the one of uTLS `HelloChrome_133`.

use super::*;
use std::collections::BTreeMap;
use tokio::{io::AsyncReadExt, net::TcpListener};

/// ClientHello record of metacubex/utls v1.8.8 `HelloChrome_Auto`, see `tests/utls-hello`.
const UTLS_HELLO: &str = include_str!("../../tests/utls-chrome133-hello.hex");

const SERVER_NAME: &str = "v1-dy.ixigua.com";

/// All GREASE values are normalized to this one.
const GREASE: u16 = 0x0a0a;

const EXT_SERVER_NAME: u16 = 0x0000;
const EXT_STATUS_REQUEST: u16 = 0x0005;
const EXT_SUPPORTED_GROUPS: u16 = 0x000a;
const EXT_EC_POINT_FORMATS: u16 = 0x000b;
const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d;
const EXT_ALPN: u16 = 0x0010;
const EXT_SCT: u16 = 0x0012;
const EXT_PADDING: u16 = 0x0015;
const EXT_EXTENDED_MASTER_SECRET: u16 = 0x0017;
const EXT_COMPRESS_CERTIFICATE: u16 = 0x001b;
const EXT_SESSION_TICKET: u16 = 0x0023;
const EXT_PRE_SHARED_KEY: u16 = 0x0029;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
const EXT_PSK_KEY_EXCHANGE_MODES: u16 = 0x002d;
const EXT_KEY_SHARE: u16 = 0x0033;
const EXT_ALPS: u16 = 0x44cd;
const EXT_ECH: u16 = 0xfe0d;
const EXT_RENEGOTIATION_INFO: u16 = 0xff01;

/// Extensions whose content is compared byte for byte.
const FIXED_EXTENSIONS: [u16; 6] = [
    EXT_STATUS_REQUEST,
    EXT_EC_POINT_FORMATS,
    EXT_SCT,
    EXT_EXTENDED_MASTER_SECRET,
    EXT_SESSION_TICKET,
    EXT_RENEGOTIATION_INFO,
];

const X25519_MLKEM768: u16 = 0x11ec;
const X25519: u16 = 0x001d;

fn grease(value: u16) -> u16 {
    if value & 0x0f0f == 0x0a0a && value >> 8 == value & 0xff { GREASE } else { value }
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn bytes(&mut self, len: usize) -> &'a [u8] {
        let (head, tail) = self.0.split_at(len);
        self.0 = tail;
        head
    }

    fn u8(&mut self) -> u8 {
        self.bytes(1)[0]
    }

    fn u16(&mut self) -> u16 {
        u16::from_be_bytes(self.bytes(2).try_into().unwrap())
    }

    fn u24(&mut self) -> usize {
        self.bytes(3).iter().fold(0, |len, &b| len << 8 | b as usize)
    }

    fn vec8(&mut self) -> Reader<'a> {
        let len = self.u8().into();
        Reader(self.bytes(len))
    }

    fn vec16(&mut self) -> Reader<'a> {
        let len = self.u16().into();
        Reader(self.bytes(len))
    }

    fn finish(self) {
        assert!(self.is_empty(), "{} trailing bytes", self.0.len());
    }

    /// Remaining content as GREASE-normalized `u16` values.
    fn u16s(mut self) -> Vec<u16> {
        let mut values = Vec::new();
        while !self.is_empty() {
            values.push(grease(self.u16()));
        }
        values
    }

    /// Remaining content as a list of protocol names with one-byte lengths.
    fn protocols(mut self) -> Vec<String> {
        let mut names = Vec::new();
        while !self.is_empty() {
            names.push(String::from_utf8(self.vec8().0.to_vec()).unwrap());
        }
        names
    }
}

/// Fields of a ClientHello that are compared, with GREASE values normalized.
#[derive(Debug, PartialEq)]
struct Hello {
    record_version: u16,
    session_id_len: usize,
    ciphers: Vec<u16>,
    compression: Vec<u8>,
    extension_types: BTreeMap<u16, usize>,
    grease_extensions: Vec<Vec<u8>>,
    fixed_extensions: BTreeMap<u16, Vec<u8>>,
    server_name: String,
    groups: Vec<u16>,
    key_shares: Vec<(u16, usize)>,
    signature_algorithms: Vec<u16>,
    versions: Vec<u16>,
    psk_modes: Vec<u8>,
    alpn: Vec<String>,
    alps: Vec<String>,
    compress_certificate: Vec<u16>,
    /// ECH type, KDF, AEAD and encapsulated key length; the GREASE payload length is random.
    ech: (u8, u16, u16, usize),
}

impl Hello {
    /// Parses the ClientHello carried by `records`, which are TLS handshake records.
    fn parse(records: &[u8]) -> Self {
        let record_version = u16::from_be_bytes([records[1], records[2]]);
        let msg = handshake_message(records).expect("incomplete ClientHello");

        let mut msg = Reader(&msg);
        assert_eq!(msg.u8(), 1, "not a ClientHello");
        let len = msg.u24();
        let mut body = Reader(msg.bytes(len));
        msg.finish();

        assert_eq!(body.u16(), 0x0303);
        body.bytes(32);
        let session_id_len = body.vec8().0.len();
        let ciphers = body.vec16().u16s();
        let compression = body.vec8().0.to_vec();
        let mut exts = body.vec16();
        body.finish();

        let mut extensions = Vec::new();
        while !exts.is_empty() {
            let ty = grease(exts.u16());
            extensions.push((ty, exts.vec16().0));
        }

        let mut extension_types = BTreeMap::new();
        for (ty, _) in &extensions {
            *extension_types.entry(*ty).or_default() += 1;
        }
        let mut grease_extensions: Vec<_> =
            extensions.iter().filter(|(ty, _)| *ty == GREASE).map(|(_, data)| data.to_vec()).collect();
        grease_extensions.sort();
        let ext = |ty: u16| {
            let mut found = extensions.iter().filter(|(t, _)| *t == ty);
            let data = found.next().unwrap_or_else(|| panic!("extension {ty:#06x} missing")).1;
            assert!(found.next().is_none(), "extension {ty:#06x} repeated");
            Reader(data)
        };
        let fixed_extensions = FIXED_EXTENSIONS.iter().map(|&ty| (ty, ext(ty).0.to_vec())).collect();

        let mut names = ext(EXT_SERVER_NAME).vec16();
        assert_eq!(names.u8(), 0, "SNI is not a host name");
        let server_name = String::from_utf8(names.vec16().0.to_vec()).unwrap();
        names.finish();

        let mut shares = ext(EXT_KEY_SHARE).vec16();
        let mut key_shares = Vec::new();
        while !shares.is_empty() {
            key_shares.push((grease(shares.u16()), shares.vec16().0.len()));
        }

        let mut ech_ext = ext(EXT_ECH);
        let ech = (ech_ext.u8(), ech_ext.u16(), ech_ext.u16(), {
            ech_ext.u8();
            ech_ext.vec16().0.len()
        });
        let payload_len = ech_ext.vec16().0.len();
        ech_ext.finish();
        assert!([144, 176, 208, 240].contains(&payload_len), "ECH GREASE payload of {payload_len} bytes");

        Self {
            record_version,
            session_id_len,
            ciphers,
            compression,
            extension_types,
            grease_extensions,
            fixed_extensions,
            server_name,
            groups: ext(EXT_SUPPORTED_GROUPS).vec16().u16s(),
            key_shares,
            signature_algorithms: ext(EXT_SIGNATURE_ALGORITHMS).vec16().u16s(),
            versions: ext(EXT_SUPPORTED_VERSIONS).vec8().u16s(),
            psk_modes: ext(EXT_PSK_KEY_EXCHANGE_MODES).vec8().0.to_vec(),
            alpn: ext(EXT_ALPN).vec16().protocols(),
            alps: ext(EXT_ALPS).vec16().protocols(),
            compress_certificate: ext(EXT_COMPRESS_CERTIFICATE).vec8().u16s(),
            ech,
        }
    }
}

/// Reassembles the first handshake message from complete handshake records.
///
/// Returns `None` if the records do not contain the whole message yet.
fn handshake_message(mut records: &[u8]) -> Option<Vec<u8>> {
    let mut msg = Vec::new();
    while !records.is_empty() {
        let mut record = Reader(records);
        assert_eq!(record.u8(), 22, "not a handshake record");
        record.u16();
        msg.extend_from_slice(record.vec16().0);
        records = record.0;
    }
    if msg.len() < 4 {
        return None;
    }
    let len = 4 + Reader(&msg[1..4]).u24();
    (msg.len() >= len).then(|| msg[..len].to_vec())
}

fn decode_hex(hex: &str) -> Vec<u8> {
    let hex = hex.trim();
    (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()).collect()
}

/// Captures the handshake records our connector sends as ClientHello.
async fn capture_hello() -> Vec<u8> {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mut tls = chrome_connector_builder().unwrap();
    tls.set_verify(SslVerifyMode::NONE);
    let cfg = AnyTlsCfg { server_name: Some(SERVER_NAME.into()), ..Default::default() };
    let connector = AnyTlsConnector::new([addr.to_string()], target(), "secret", tls.build(), cfg).unwrap();
    let tag = AnyTlsLinkTag::new(addr, target());
    let client = tokio::spawn(async move { connector.connect(&tag).await.map(drop) });

    let (mut tcp, _) = listener.accept().await.unwrap();
    let mut records = Vec::new();
    while handshake_message(&records).is_none() {
        let mut header = [0; 5];
        tcp.read_exact(&mut header).await.unwrap();
        let mut fragment = vec![0; u16::from_be_bytes([header[3], header[4]]).into()];
        tcp.read_exact(&mut fragment).await.unwrap();
        records.extend(header);
        records.extend(fragment);
    }
    drop(tcp);
    assert!(client.await.unwrap().is_err());
    records
}

#[tokio::test]
async fn chrome_hello_matches_utls() {
    let utls = Hello::parse(&decode_hex(UTLS_HELLO));
    let ours = Hello::parse(&capture_hello().await);

    for hello in [&utls, &ours] {
        assert_eq!(hello.extension_types.get(&GREASE), Some(&2));
        assert!(!hello.extension_types.contains_key(&EXT_PRE_SHARED_KEY));
        assert!(!hello.extension_types.contains_key(&EXT_PADDING));
        assert_eq!(hello.server_name, SERVER_NAME);
        assert_eq!(hello.alpn, ["h2", "http/1.1"]);
        assert_eq!(hello.alps, ["h2"]);
        assert_eq!(hello.compress_certificate, [0x0002]);
        assert_eq!(hello.key_shares[1..], [(X25519_MLKEM768, 1216), (X25519, 32)]);
    }

    assert_eq!(ours.extension_types, utls.extension_types);
    assert_eq!(ours.ciphers, utls.ciphers);
    assert_eq!(ours.groups, utls.groups);
    assert_eq!(ours.key_shares, utls.key_shares);
    assert_eq!(ours.signature_algorithms, utls.signature_algorithms);
    assert_eq!(ours.versions, utls.versions);
    assert_eq!(ours.psk_modes, utls.psk_modes);
    assert_eq!(ours.fixed_extensions, utls.fixed_extensions);
    assert_eq!(ours, utls);
}
