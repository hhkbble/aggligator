// Derived from shoes (https://github.com/cfal/shoes), src/anytls/anytls_client_session.rs,
// commit 60ed3838b346268615c81e4eace4e15e717da23e.
// Copyright (c) 2021-2023 Alex Lau <github@alau.ca>.
// Licensed under the MIT License; see the NOTICE file of this crate.

//! AnyTLS client session over one TLS connection.

use aggligator::io::IoBox;
use bytes::{BufMut, Bytes, BytesMut};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeSet, HashMap},
    io,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU8, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::{Notify, mpsc, oneshot},
    time::timeout,
};
use tokio_util::sync::CancellationToken;

use crate::{
    SynAckTimeoutAction,
    addr::AnyTlsTarget,
    frame::{Command, HEADER_SIZE, StringMap, decode_header, encode_frame, encode_waste},
    padding::{CHECK_MARK, PaddingScheme, PaddingSlot},
    pool::PoolSession,
    stream::{STREAM_QUEUE, StreamRead, StreamWrite},
};

/// Capacity, in messages, of the session write queue.
pub(crate) const SESSION_QUEUE: usize = 16;

/// Time to wait for `cmdSYNACK` of a stream opened with id 2 or higher on a v2 session.
pub(crate) const SYNACK_TIMEOUT: Duration = Duration::from_secs(3);

/// Upper bound for coalescing queued messages into one write once padding has stopped.
const WRITE_BATCH: usize = 65_536;

/// Value of the `client` key in `cmdSettings`.
const CLIENT_NAME: &str = concat!("aggligator-anytls/", env!("CARGO_PKG_VERSION"));

/// SHA-256 of the password, sent for authentication.
pub(crate) fn password_hash(password: &str) -> [u8; 32] {
    Sha256::digest(password.as_bytes()).into()
}

fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "AnyTLS session closed")
}

enum Outgoing {
    /// Pre-encoded frames written as one padded packet.
    Raw(Bytes),
    /// A single frame.
    Frame(Command, u32, Bytes),
    /// FIN for a stream; closes the TLS connection afterwards if `close` is set.
    Fin { stream_id: u32, close: bool },
}

/// One AnyTLS session, i.e. one TLS connection carrying streams.
pub(crate) struct Session {
    tx: mpsc::Sender<Outgoing>,
    heartbeats: Arc<Heartbeats>,
    dead: CancellationToken,
    streams: Mutex<HashMap<u32, mpsc::Sender<io::Result<Bytes>>>>,
    synacks: Mutex<HashMap<u32, oneshot::Sender<Result<(), String>>>>,
    peer_version: AtomicU8,
    pending_settings: Mutex<Option<BytesMut>>,
    slot: Arc<PaddingSlot>,
    exclusive: bool,
}

impl Session {
    /// Authenticates on an established TLS connection and starts the session tasks.
    ///
    /// The padding scheme is snapshot from `slot` now and used for the lifetime of the session.
    /// If `exclusive` is set, the TLS connection is closed after the FIN of the first stream.
    pub(crate) async fn start<IO>(
        mut io: IO, password_hash: &[u8; 32], slot: Arc<PaddingSlot>, exclusive: bool,
    ) -> io::Result<Arc<Self>>
    where
        IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let padding = slot.load();

        let padding_len = padding.sizes(0).first().copied().unwrap_or(0).clamp(0, u16::MAX as i32) as usize;
        let mut auth = BytesMut::with_capacity(34 + padding_len);
        auth.put_slice(password_hash);
        auth.put_u16(padding_len as u16);
        auth.put_bytes(0, padding_len);
        io.write_all(&auth).await?;
        io.flush().await?;

        let mut settings = StringMap::new();
        settings.insert("v", "2");
        settings.insert("client", CLIENT_NAME);
        settings.insert("padding-md5", padding.md5());
        let mut pending_settings = BytesMut::new();
        encode_frame(&mut pending_settings, Command::Settings, 0, &settings.to_bytes());

        let (tx, rx) = mpsc::channel(SESSION_QUEUE);
        let heartbeats = Arc::new(Heartbeats::default());
        let dead = CancellationToken::new();
        let session = Arc::new(Self {
            tx,
            heartbeats: heartbeats.clone(),
            dead: dead.clone(),
            streams: Mutex::new(HashMap::new()),
            synacks: Mutex::new(HashMap::new()),
            peer_version: AtomicU8::new(0),
            pending_settings: Mutex::new(Some(pending_settings)),
            slot,
            exclusive,
        });

        let (read, write) = tokio::io::split(io);
        tokio::spawn(writer_task(write, rx, heartbeats, dead, padding));
        tokio::spawn(session.clone().reader_task(read));

        Ok(session)
    }

    /// Protocol version reported by the server in `cmdServerSettings`, or 0.
    pub(crate) fn peer_version(&self) -> u8 {
        self.peer_version.load(Ordering::Acquire)
    }

    /// Opens a stream to `target`.
    ///
    /// The first stream of the session takes the buffered `cmdSettings` and is sent
    /// together with its `cmdSYN` and target address as one packet. Callers must not
    /// open other streams before the first one has returned.
    ///
    /// For stream ids of 2 or higher on a session whose server reported version 2,
    /// this waits for `cmdSYNACK` of this stream after sending the target address.
    ///
    /// `keep` is dropped after the stream's FIN has been queued, or when opening fails.
    pub(crate) async fn open_stream(
        self: &Arc<Self>, stream_id: u32, target: &AnyTlsTarget, keep: Option<Box<dyn Send + Sync>>,
        on_timeout: SynAckTimeoutAction,
    ) -> io::Result<IoBox> {
        if self.is_dead() {
            return Err(closed());
        }

        let (read_tx, read_rx) = mpsc::channel(STREAM_QUEUE);
        let (write_tx, write_rx) = mpsc::channel(STREAM_QUEUE);
        self.streams.lock().unwrap().insert(stream_id, read_tx);

        let synack_rx = if stream_id >= 2 && self.peer_version() >= 2 {
            let (tx, rx) = oneshot::channel();
            self.synacks.lock().unwrap().insert(stream_id, tx);
            Some(rx)
        } else {
            None
        };

        let mut addr = BytesMut::new();
        target.encode(&mut addr);
        let pending_settings = self.pending_settings.lock().unwrap().take();
        let sent = match pending_settings {
            Some(mut buf) => {
                encode_frame(&mut buf, Command::Syn, stream_id, &[]);
                encode_frame(&mut buf, Command::Psh, stream_id, &addr);
                self.send(Outgoing::Raw(buf.freeze())).await
            }
            None => match self.send(Outgoing::Frame(Command::Syn, stream_id, Bytes::new())).await {
                Ok(()) => self.send(Outgoing::Frame(Command::Psh, stream_id, addr.freeze())).await,
                Err(err) => Err(err),
            },
        };
        if let Err(err) = sent {
            self.streams.lock().unwrap().remove(&stream_id);
            self.synacks.lock().unwrap().remove(&stream_id);
            return Err(err);
        }

        tokio::spawn(self.clone().forward(stream_id, write_rx, keep));

        if let Some(synack_rx) = synack_rx {
            let err = match timeout(SYNACK_TIMEOUT, synack_rx).await {
                Ok(Ok(Ok(()))) => None,
                Ok(Ok(Err(msg))) => Some(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    format!("AnyTLS server refused stream: {msg}"),
                )),
                Ok(Err(_)) => Some(closed()),
                Err(_) => {
                    self.synacks.lock().unwrap().remove(&stream_id);
                    if on_timeout == SynAckTimeoutAction::CloseSession {
                        tracing::debug!(stream_id, "SYNACK timeout, closing AnyTLS session");
                        self.terminate();
                    }
                    Some(io::Error::new(io::ErrorKind::TimedOut, "AnyTLS SYNACK timeout"))
                }
            };
            if let Some(err) = err {
                self.streams.lock().unwrap().remove(&stream_id);
                return Err(err);
            }
        }

        Ok(IoBox::new(StreamRead::new(read_rx), StreamWrite::new(write_tx, self.dead.clone())))
    }

    async fn send(&self, msg: Outgoing) -> io::Result<()> {
        tokio::select! {
            biased;
            () = self.dead.cancelled() => Err(closed()),
            res = self.tx.send(msg) => res.map_err(|_| closed()),
        }
    }

    /// Moves data from a stream's write queue into the session write queue,
    /// then sends FIN once the write half has been closed or dropped.
    async fn forward(
        self: Arc<Self>, stream_id: u32, mut rx: mpsc::Receiver<Bytes>, keep: Option<Box<dyn Send + Sync>>,
    ) {
        loop {
            let data = tokio::select! {
                biased;
                () = self.dead.cancelled() => return,
                data = rx.recv() => data,
            };
            let Some(data) = data else { break };
            if self.send(Outgoing::Frame(Command::Psh, stream_id, data)).await.is_err() {
                return;
            }
        }

        self.streams.lock().unwrap().remove(&stream_id);
        let _ = self.send(Outgoing::Fin { stream_id, close: self.exclusive }).await;
        drop(keep);
    }

    async fn reader_task<R>(self: Arc<Self>, mut read: R)
    where
        R: AsyncRead + Unpin,
    {
        let err = tokio::select! {
            () = self.dead.cancelled() => closed(),
            res = self.read_loop(&mut read) => res.err().unwrap_or_else(closed),
        };
        tracing::debug!(%err, "AnyTLS session reader stopped");
        self.fail(&err);
    }

    async fn read_loop<R>(&self, read: &mut R) -> io::Result<()>
    where
        R: AsyncRead + Unpin,
    {
        let mut header = [0; HEADER_SIZE];
        loop {
            if let Err(err) = read.read_exact(&mut header).await {
                return Err(match err.kind() {
                    io::ErrorKind::UnexpectedEof => {
                        io::Error::new(io::ErrorKind::ConnectionReset, "AnyTLS server closed connection")
                    }
                    _ => err,
                });
            }
            let (cmd, stream_id, len) = decode_header(&header);
            let mut data = vec![0; len as usize];
            read.read_exact(&mut data).await?;
            let data = Bytes::from(data);

            match Command::from_u8(cmd) {
                Some(Command::Psh) => {
                    let tx = self.streams.lock().unwrap().get(&stream_id).cloned();
                    if let Some(tx) = tx
                        && !data.is_empty()
                    {
                        let _ = tx.send(Ok(data)).await;
                    }
                }
                Some(Command::Fin) => {
                    self.streams.lock().unwrap().remove(&stream_id);
                }
                Some(Command::SynAck) => {
                    let result =
                        if data.is_empty() { Ok(()) } else { Err(String::from_utf8_lossy(&data).into_owned()) };
                    let waiter = self.synacks.lock().unwrap().remove(&stream_id);
                    match (waiter, result) {
                        (Some(waiter), result) => {
                            let _ = waiter.send(result);
                        }
                        (None, Err(msg)) => {
                            if let Some(tx) = self.streams.lock().unwrap().remove(&stream_id) {
                                let _ = tx.try_send(Err(io::Error::new(
                                    io::ErrorKind::ConnectionRefused,
                                    format!("AnyTLS server refused stream: {msg}"),
                                )));
                            }
                        }
                        (None, Ok(())) => (),
                    }
                }
                Some(Command::ServerSettings) => {
                    let settings = StringMap::from_bytes(&data);
                    if let Some(version) = settings.get("v").and_then(|v| v.trim().parse().ok()) {
                        self.peer_version.store(version, Ordering::Release);
                    }
                }
                Some(Command::UpdatePaddingScheme) => match PaddingScheme::parse(&data) {
                    Some(scheme) => {
                        tracing::debug!(md5 = scheme.md5(), "AnyTLS padding scheme updated");
                        self.slot.store(Arc::new(scheme));
                    }
                    None => tracing::warn!("invalid AnyTLS padding scheme update"),
                },
                Some(Command::Alert) => {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        format!("AnyTLS server alert: {}", String::from_utf8_lossy(&data)),
                    ));
                }
                Some(Command::HeartRequest) => self.heartbeats.request(stream_id),
                Some(Command::Waste | Command::Syn | Command::Settings | Command::HeartResponse) => (),
                None => tracing::debug!(cmd, "ignoring unknown AnyTLS command"),
            }
        }
    }

    /// Marks the session dead and fails all of its streams.
    fn fail(&self, err: &io::Error) {
        self.dead.cancel();
        let streams = std::mem::take(&mut *self.streams.lock().unwrap());
        for tx in streams.into_values() {
            let _ = tx.try_send(Err(io::Error::new(err.kind(), err.to_string())));
        }
        self.synacks.lock().unwrap().clear();
    }
}

impl PoolSession for Session {
    fn is_dead(&self) -> bool {
        self.dead.is_cancelled()
    }

    fn terminate(&self) {
        self.dead.cancel();
    }
}

/// Stream ids owed a `cmdHeartResponse`.
///
/// The reader must not block on the bounded write queue, so it records requests here
/// and wakes the writer, which answers them before taking the next queued message.
#[derive(Default)]
struct Heartbeats {
    pending: Mutex<BTreeSet<u32>>,
    notify: Notify,
}

impl Heartbeats {
    fn request(&self, stream_id: u32) {
        self.pending.lock().unwrap().insert(stream_id);
        self.notify.notify_one();
    }

    fn take(&self) -> BTreeSet<u32> {
        std::mem::take(&mut *self.pending.lock().unwrap())
    }
}

async fn writer_task<W>(
    mut write: W, mut rx: mpsc::Receiver<Outgoing>, heartbeats: Arc<Heartbeats>, dead: CancellationToken,
    padding: Arc<PaddingScheme>,
) where
    W: AsyncWrite + Unpin,
{
    let mut padder = Padder { scheme: padding, pkt: 0, active: true };
    let res = tokio::select! {
        () = dead.cancelled() => Ok(()),
        res = write_loop(&mut write, &mut rx, &heartbeats, &mut padder) => res,
    };
    if let Err(err) = res {
        tracing::debug!(%err, "AnyTLS session writer failed");
    }
    dead.cancel();
}

async fn write_loop<W>(
    write: &mut W, rx: &mut mpsc::Receiver<Outgoing>, heartbeats: &Heartbeats, padder: &mut Padder,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    loop {
        let responses = heartbeats.take();
        if !responses.is_empty() {
            let mut buf = BytesMut::new();
            for stream_id in responses {
                encode_frame(&mut buf, Command::HeartResponse, stream_id, &[]);
            }
            if padder.active {
                padder.write(write, &buf).await?;
            } else {
                write.write_all(&buf).await?;
            }
            write.flush().await?;
            continue;
        }

        let msg = tokio::select! {
            biased;
            () = heartbeats.notify.notified() => continue,
            msg = rx.recv() => msg,
        };
        let Some(msg) = msg else { break };

        let mut buf = BytesMut::new();
        let mut close = encode_outgoing(msg, &mut buf);

        if padder.active {
            padder.write(write, &buf).await?;
        } else {
            while !close && buf.len() < WRITE_BATCH {
                match rx.try_recv() {
                    Ok(msg) => close |= encode_outgoing(msg, &mut buf),
                    Err(_) => break,
                }
            }
            write.write_all(&buf).await?;
        }
        write.flush().await?;

        if close {
            write.shutdown().await?;
            break;
        }
    }
    Ok(())
}

fn encode_outgoing(msg: Outgoing, buf: &mut BytesMut) -> bool {
    match msg {
        Outgoing::Raw(data) => {
            buf.extend_from_slice(&data);
            false
        }
        Outgoing::Frame(cmd, stream_id, data) => {
            encode_frame(buf, cmd, stream_id, &data);
            false
        }
        Outgoing::Fin { stream_id, close } => {
            encode_frame(buf, Command::Fin, stream_id, &[]);
            close
        }
    }
}

/// Client-side packet padding, following `writeConn` of anytls-go.
struct Padder {
    scheme: Arc<PaddingScheme>,
    pkt: u32,
    active: bool,
}

impl Padder {
    /// Writes one packet, splitting it and appending `cmdWaste` as the scheme requires.
    async fn write<W>(&mut self, write: &mut W, data: &[u8]) -> io::Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        self.pkt += 1;
        if self.pkt >= self.scheme.stop() {
            self.active = false;
            return write.write_all(data).await;
        }

        let mut rest = data;
        for size in self.scheme.sizes(self.pkt) {
            if size == CHECK_MARK {
                if rest.is_empty() {
                    break;
                }
                continue;
            }

            let size = size as usize;
            if rest.len() > size {
                write.write_all(&rest[..size]).await?;
                rest = &rest[size..];
            } else if !rest.is_empty() {
                let mut buf = BytesMut::from(rest);
                let padding_len = size.saturating_sub(rest.len() + HEADER_SIZE);
                if padding_len > 0 {
                    encode_waste(&mut buf, padding_len);
                }
                write.write_all(&buf).await?;
                rest = &[];
            } else {
                let mut buf = BytesMut::new();
                encode_waste(&mut buf, size);
                write.write_all(&buf).await?;
            }
        }

        if !rest.is_empty() {
            write.write_all(rest).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
