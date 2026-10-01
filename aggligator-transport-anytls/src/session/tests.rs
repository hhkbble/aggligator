use super::*;
use std::{
    pin::Pin,
    task::{Context, Poll},
};
use tokio::{
    io::{DuplexStream, ReadBuf, duplex},
    time::sleep,
};

use crate::padding::DEFAULT_PADDING_SCHEME;

const PASSWORD: &str = "secret";

fn target() -> AnyTlsTarget {
    AnyTlsTarget::Domain("acceptor.example".into(), 5800)
}

fn target_bytes() -> Vec<u8> {
    let mut buf = BytesMut::new();
    target().encode(&mut buf);
    buf.to_vec()
}

fn slot(scheme: &[u8]) -> Arc<PaddingSlot> {
    Arc::new(PaddingSlot::new(Arc::new(PaddingScheme::parse(scheme).unwrap())))
}

type Writes = Arc<Mutex<Vec<Vec<u8>>>>;

/// Client IO that records each write call.
struct Recorder {
    inner: DuplexStream,
    writes: Writes,
}

impl AsyncRead for Recorder {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context, buf: &mut ReadBuf) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for Recorder {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let res = Pin::new(&mut this.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &res {
            this.writes.lock().unwrap().push(buf[..*n].to_vec());
        }
        res
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Server side of a session.
struct Server {
    io: DuplexStream,
}

impl Server {
    async fn read_auth(&mut self) -> Vec<u8> {
        let mut auth = vec![0; 34];
        self.io.read_exact(&mut auth).await.unwrap();
        let len = u16::from_be_bytes([auth[32], auth[33]]) as usize;
        let mut padding = vec![0; len];
        self.io.read_exact(&mut padding).await.unwrap();
        auth.extend(padding);
        auth
    }

    /// Reads the next frame, skipping padding.
    async fn read_frame(&mut self) -> (Command, u32, Bytes) {
        loop {
            let mut header = [0; HEADER_SIZE];
            self.io.read_exact(&mut header).await.unwrap();
            let (cmd, stream_id, len) = decode_header(&header);
            let mut data = vec![0; len as usize];
            self.io.read_exact(&mut data).await.unwrap();
            let cmd = Command::from_u8(cmd).unwrap();
            if cmd != Command::Waste {
                return (cmd, stream_id, data.into());
            }
        }
    }

    async fn expect_frame(&mut self, cmd: Command, stream_id: u32) -> Bytes {
        let (c, s, data) = self.read_frame().await;
        assert_eq!((c, s), (cmd, stream_id), "unexpected frame");
        data
    }

    async fn write_frame(&mut self, cmd: Command, stream_id: u32, data: &[u8]) {
        let mut buf = BytesMut::new();
        encode_frame(&mut buf, cmd, stream_id, data);
        self.io.write_all(&buf).await.unwrap();
    }

    /// Reads the open sequence of a stream.
    async fn accept_stream(&mut self, stream_id: u32) {
        self.expect_frame(Command::Syn, stream_id).await;
        assert_eq!(self.expect_frame(Command::Psh, stream_id).await, target_bytes());
    }

    /// Reads auth, settings and the first stream; replies with version 2 if `v2` is set.
    async fn handshake(&mut self, v2: bool) -> StringMap {
        self.read_auth().await;
        let settings = StringMap::from_bytes(&self.expect_frame(Command::Settings, 0).await);
        self.accept_stream(1).await;
        if v2 {
            self.write_frame(Command::ServerSettings, 0, b"v=2").await;
        }
        settings
    }
}

async fn start_with(slot: Arc<PaddingSlot>, exclusive: bool, buffer: usize) -> (Arc<Session>, Server, Writes) {
    let (client, server) = duplex(buffer);
    let writes = Writes::default();
    let io = Recorder { inner: client, writes: writes.clone() };
    let session = Session::start(io, &password_hash(PASSWORD), slot, exclusive).await.unwrap();
    (session, Server { io: server }, writes)
}

async fn start(exclusive: bool) -> (Arc<Session>, Server, Writes) {
    start_with(Arc::new(PaddingSlot::default()), exclusive, 1 << 20).await
}

async fn open(session: &Arc<Session>, stream_id: u32, action: SynAckTimeoutAction) -> io::Result<IoBox> {
    session.open_stream(stream_id, &target(), None, action).await
}

async fn wait_for_v2(session: &Session) {
    while session.peer_version() < 2 {
        tokio::task::yield_now().await;
    }
}

/// Opens stream 1 on a version 2 session and opens stream 2 concurrently.
async fn open_second(
    action: SynAckTimeoutAction,
) -> (Arc<Session>, Server, IoBox, tokio::task::JoinHandle<io::Result<IoBox>>) {
    let (session, mut server, _) = start(false).await;
    let first = open(&session, 1, action).await.unwrap();
    server.handshake(true).await;
    wait_for_v2(&session).await;

    let second = tokio::spawn({
        let session = session.clone();
        async move { open(&session, 2, action).await }
    });
    server.accept_stream(2).await;
    (session, server, first, second)
}

#[tokio::test]
async fn auth_and_settings_use_default_padding() {
    let (session, mut server, writes) = start(false).await;
    let _io = open(&session, 1, SynAckTimeoutAction::CloseSession).await.unwrap();

    let auth = server.read_auth().await;
    assert_eq!(auth.len(), 64);
    assert_eq!(&auth[..32], &password_hash(PASSWORD));
    assert_eq!(&auth[32..34], &[0, 30]);
    assert!(auth[34..].iter().all(|&b| b == 0));
    assert_eq!(writes.lock().unwrap()[0], auth);

    let settings = StringMap::from_bytes(&server.expect_frame(Command::Settings, 0).await);
    assert_eq!(
        settings.to_bytes(),
        format!("v=2\nclient={CLIENT_NAME}\npadding-md5=75cff2ad89aadf5e257059ee571ebe11").into_bytes()
    );
    server.accept_stream(1).await;
}

#[tokio::test]
async fn first_stream_is_sent_with_settings_as_one_packet() {
    let (session, mut server, writes) = start_with(slot(b"stop=8\n0=30-30\n1=1000-1000"), false, 1 << 20).await;
    let _io = open(&session, 1, SynAckTimeoutAction::CloseSession).await.unwrap();
    server.handshake(false).await;

    let writes = writes.lock().unwrap().clone();
    assert_eq!(writes.len(), 2, "auth and one packet");
    let packet = &writes[1];
    assert_eq!(packet.len(), 1000);

    let mut frames = Vec::new();
    let mut rest = &packet[..];
    while !rest.is_empty() {
        let (cmd, stream_id, len) = decode_header(rest[..HEADER_SIZE].try_into().unwrap());
        frames.push((Command::from_u8(cmd).unwrap(), stream_id));
        rest = &rest[HEADER_SIZE + len as usize..];
    }
    assert_eq!(frames, [(Command::Settings, 0), (Command::Syn, 1), (Command::Psh, 1), (Command::Waste, 0)]);
}

#[tokio::test]
async fn synack_is_awaited_per_stream() {
    let (session, mut server, _first, second) = open_second(SynAckTimeoutAction::CloseSession).await;

    let third = tokio::spawn({
        let session = session.clone();
        async move { open(&session, 3, SynAckTimeoutAction::CloseSession).await }
    });
    server.accept_stream(3).await;

    server.write_frame(Command::SynAck, 3, b"").await;
    third.await.unwrap().unwrap();
    assert!(!second.is_finished());

    server.write_frame(Command::SynAck, 2, b"").await;
    second.await.unwrap().unwrap();
}

#[tokio::test]
async fn version_1_does_not_wait_for_synack() {
    let (session, mut server, _) = start(false).await;
    let _first = open(&session, 1, SynAckTimeoutAction::CloseSession).await.unwrap();
    server.handshake(false).await;

    let _second = open(&session, 2, SynAckTimeoutAction::CloseSession).await.unwrap();
    server.accept_stream(2).await;
}

#[tokio::test(start_paused = true)]
async fn synack_timeout_closes_stream_only() {
    let (session, mut server, mut first, second) = open_second(SynAckTimeoutAction::CloseStream).await;

    let err = second.await.unwrap().err().unwrap();
    assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    server.expect_frame(Command::Fin, 2).await;
    assert!(!session.is_dead());

    first.write_all(b"ping").await.unwrap();
    assert_eq!(server.expect_frame(Command::Psh, 1).await, &b"ping"[..]);
    server.write_frame(Command::Psh, 1, b"pong").await;
    let mut buf = [0; 4];
    first.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"pong");
}

#[tokio::test(start_paused = true)]
async fn synack_timeout_closes_session() {
    let (session, _server, mut first, second) = open_second(SynAckTimeoutAction::CloseSession).await;

    let err = second.await.unwrap().err().unwrap();
    assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    assert!(session.is_dead());

    let mut buf = [0; 4];
    assert!(first.read(&mut buf).await.is_err());
    assert!(first.write_all(b"ping").await.is_err());
}

#[tokio::test]
async fn error_synack_fails_only_its_stream() {
    let (session, mut server, mut first, second) = open_second(SynAckTimeoutAction::CloseSession).await;

    server.write_frame(Command::SynAck, 2, b"dial failed").await;
    let err = second.await.unwrap().err().unwrap();
    assert_eq!(err.kind(), io::ErrorKind::ConnectionRefused);
    server.expect_frame(Command::Fin, 2).await;
    assert!(!session.is_dead());

    first.write_all(b"ping").await.unwrap();
    assert_eq!(server.expect_frame(Command::Psh, 1).await, &b"ping"[..]);
}

#[tokio::test]
async fn dropping_stream_sends_fin_after_data() {
    let (session, mut server, _) = start(false).await;
    let mut io = open(&session, 1, SynAckTimeoutAction::CloseSession).await.unwrap();
    server.handshake(false).await;

    io.write_all(b"hello").await.unwrap();
    let (read, write) = io.into_split();
    drop(write);
    drop(read);

    assert_eq!(server.expect_frame(Command::Psh, 1).await, &b"hello"[..]);
    server.expect_frame(Command::Fin, 1).await;
    assert!(!session.is_dead());
}

#[tokio::test(start_paused = true)]
async fn write_backpressure_keeps_fin() {
    let (session, mut server, _) = start_with(Arc::new(PaddingSlot::default()), false, 16 * 1024).await;
    let mut io = open(&session, 1, SynAckTimeoutAction::CloseSession).await.unwrap();
    server.handshake(false).await;

    let chunk = vec![0x55; 8192];
    let mut written = 0;
    loop {
        match timeout(Duration::from_secs(1), io.write(&chunk)).await {
            Ok(res) => written += res.unwrap(),
            Err(_) => break,
        }
        assert!(written < 64 * 1024 * 1024, "writes never blocked");
    }
    drop(io);

    let mut received = 0;
    loop {
        match server.read_frame().await {
            (Command::Psh, 1, data) => received += data.len(),
            (Command::Fin, 1, _) => break,
            other => panic!("unexpected frame {other:?}"),
        }
    }
    assert_eq!(received, written);
}

#[tokio::test]
async fn exclusive_session_closes_after_fin() {
    let (session, mut server, _) = start(true).await;
    let io = open(&session, 1, SynAckTimeoutAction::CloseSession).await.unwrap();
    server.handshake(false).await;

    drop(io);
    server.expect_frame(Command::Fin, 1).await;
    let mut rest = Vec::new();
    server.io.read_to_end(&mut rest).await.unwrap();
    while !rest.is_empty() {
        let (cmd, _, len) = decode_header(rest[..HEADER_SIZE].try_into().unwrap());
        assert_eq!(cmd, Command::Waste as u8, "only padding may follow FIN");
        rest.drain(..HEADER_SIZE + len as usize);
    }
    while !session.is_dead() {
        tokio::task::yield_now().await;
    }
}

#[tokio::test]
async fn padding_update_applies_to_next_session() {
    let shared = Arc::new(PaddingSlot::default());
    let (first, mut server, writes) = start_with(shared.clone(), false, 1 << 20).await;
    let mut io = open(&first, 1, SynAckTimeoutAction::CloseSession).await.unwrap();
    server.handshake(false).await;

    let new_scheme = b"stop=1\n0=40-40";
    server.write_frame(Command::UpdatePaddingScheme, 0, new_scheme).await;
    let new_md5 = PaddingScheme::parse(new_scheme).unwrap().md5().to_string();
    while shared.load().md5() != new_md5 {
        tokio::task::yield_now().await;
    }

    // The existing session keeps padding its packets with the default scheme.
    let before = writes.lock().unwrap().len();
    io.write_all(b"x").await.unwrap();
    server.expect_frame(Command::Psh, 1).await;
    let packet: usize = writes.lock().unwrap()[before..].iter().map(Vec::len).sum();
    assert!(packet >= 400, "packet 2 not padded: {packet} bytes");

    let (second, mut server, _) = start_with(shared, false, 1 << 20).await;
    let _io = open(&second, 1, SynAckTimeoutAction::CloseSession).await.unwrap();
    let auth = server.read_auth().await;
    assert_eq!(auth.len(), 34 + 40);
    let settings = StringMap::from_bytes(&server.expect_frame(Command::Settings, 0).await);
    assert_eq!(settings.get("padding-md5"), Some(new_md5.as_str()));
    assert_ne!(new_md5, PaddingScheme::parse(DEFAULT_PADDING_SCHEME).unwrap().md5());
}

#[tokio::test]
async fn heartbeat_is_answered() {
    let (session, mut server, _) = start(false).await;
    let _io = open(&session, 1, SynAckTimeoutAction::CloseSession).await.unwrap();
    server.handshake(true).await;

    server.write_frame(Command::HeartRequest, 0, b"").await;
    server.expect_frame(Command::HeartResponse, 0).await;
}

#[tokio::test(start_paused = true)]
async fn heartbeat_is_answered_when_write_queue_is_full() {
    let (session, mut server, _) = start_with(Arc::new(PaddingSlot::default()), false, 16 * 1024).await;
    let mut io = open(&session, 1, SynAckTimeoutAction::CloseSession).await.unwrap();
    server.handshake(true).await;

    // Fill the TLS connection and the session write queue.
    let chunk = vec![0x55; 8192];
    while timeout(Duration::from_secs(1), io.write(&chunk)).await.is_ok() {}

    server.write_frame(Command::HeartRequest, 0, b"").await;
    sleep(Duration::from_millis(100)).await;
    drop(io);

    loop {
        match server.read_frame().await {
            (Command::HeartResponse, 0, _) => break,
            (Command::Fin, 1, _) => panic!("heartbeat response was dropped"),
            _ => (),
        }
    }
}

#[tokio::test]
async fn alert_fails_session() {
    let (session, mut server, _) = start(false).await;
    let mut io = open(&session, 1, SynAckTimeoutAction::CloseSession).await.unwrap();
    server.handshake(false).await;

    server.write_frame(Command::Alert, 0, b"bad client").await;
    let mut buf = [0; 1];
    let err = io.read(&mut buf).await.unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::ConnectionAborted);
    assert!(session.is_dead());
}

#[tokio::test]
async fn server_fin_ends_stream() {
    let (session, mut server, _) = start(false).await;
    let mut io = open(&session, 1, SynAckTimeoutAction::CloseSession).await.unwrap();
    server.handshake(false).await;

    server.write_frame(Command::Psh, 1, b"bye").await;
    server.write_frame(Command::Fin, 1, b"").await;
    let mut buf = Vec::new();
    io.read_to_end(&mut buf).await.unwrap();
    assert_eq!(buf, b"bye");
}
