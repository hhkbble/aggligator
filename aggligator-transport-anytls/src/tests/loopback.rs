//! Connector tests against a local fake AnyTLS server over TLS.

use super::*;
use bytes::BytesMut;
use rustls::{
    RootCertStore, ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};
use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpListener,
    time::timeout,
};
use tokio_rustls::TlsAcceptor;

use crate::frame::{Command, HEADER_SIZE, decode_header, encode_frame};

const PASSWORD: &str = "secret";

#[derive(Default)]
struct Stats {
    connections: AtomicUsize,
    closed: AtomicUsize,
    max_stream_id: AtomicUsize,
}

struct FakeServer {
    addr: SocketAddr,
    tls: Arc<ClientConfig>,
    stats: Arc<Stats>,
}

impl FakeServer {
    /// Starts a server that acknowledges streams (protocol version 2) and echoes stream data.
    async fn start() -> Self {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_der = CertificateDer::from(cert.cert.der().to_vec());
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));

        let server_cfg = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.clone()], key_der)
            .unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(cert_der).unwrap();
        let tls = Arc::new(ClientConfig::builder().with_root_certificates(roots).with_no_client_auth());

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_cfg));
        let stats = Arc::new(Stats::default());

        tokio::spawn({
            let stats = stats.clone();
            async move {
                loop {
                    let (tcp, _) = listener.accept().await.unwrap();
                    let acceptor = acceptor.clone();
                    let stats = stats.clone();
                    tokio::spawn(async move {
                        let tls = acceptor.accept(tcp).await.unwrap();
                        stats.connections.fetch_add(1, AtomicOrdering::SeqCst);
                        serve(tls, &stats).await;
                        stats.closed.fetch_add(1, AtomicOrdering::SeqCst);
                    });
                }
            }
        });

        Self { addr, tls, stats }
    }

    fn connector(&self, policy: SessionPolicy) -> AnyTlsConnector {
        let cfg = AnyTlsCfg {
            server_name: Some(ServerName::try_from("localhost").unwrap()),
            policy,
            ..Default::default()
        };
        AnyTlsConnector::new([self.addr.to_string()], target(), PASSWORD, self.tls.clone(), cfg).unwrap()
    }

    fn tag(&self) -> AnyTlsLinkTag {
        AnyTlsLinkTag::new(self.addr, target())
    }

    fn connections(&self) -> usize {
        self.stats.connections.load(AtomicOrdering::SeqCst)
    }

    fn closed(&self) -> usize {
        self.stats.closed.load(AtomicOrdering::SeqCst)
    }
}

/// Serves one session until the client closes it.
async fn serve<IO>(mut io: IO, stats: &Stats)
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let mut auth = [0; 34];
    io.read_exact(&mut auth).await.unwrap();
    assert_eq!(&auth[..32], &session::password_hash(PASSWORD));
    let mut padding = vec![0; u16::from_be_bytes([auth[32], auth[33]]) as usize];
    io.read_exact(&mut padding).await.unwrap();

    let mut opened = HashSet::new();
    loop {
        let mut header = [0; HEADER_SIZE];
        if io.read_exact(&mut header).await.is_err() {
            return;
        }
        let (cmd, stream_id, len) = decode_header(&header);
        let mut data = vec![0; len as usize];
        io.read_exact(&mut data).await.unwrap();

        let mut reply = BytesMut::new();
        match Command::from_u8(cmd).unwrap() {
            Command::Settings => encode_frame(&mut reply, Command::ServerSettings, 0, b"v=2"),
            Command::Syn => {
                stats.max_stream_id.fetch_max(stream_id as usize, AtomicOrdering::SeqCst);
            }
            Command::Psh if opened.insert(stream_id) => {
                let mut expected = BytesMut::new();
                target().encode(&mut expected);
                assert_eq!(data, expected);
                encode_frame(&mut reply, Command::SynAck, stream_id, &[]);
            }
            Command::Psh => encode_frame(&mut reply, Command::Psh, stream_id, &data),
            Command::Fin => {
                opened.remove(&stream_id);
                encode_frame(&mut reply, Command::Fin, stream_id, &[]);
            }
            _ => (),
        }
        if !reply.is_empty() && io.write_all(&reply).await.is_err() {
            return;
        }
    }
}

fn target() -> AnyTlsTarget {
    AnyTlsTarget::Domain("acceptor.example".into(), 5800)
}

fn into_io(stream: StreamBox) -> aggligator::io::IoBox {
    match stream {
        StreamBox::Io(io) => io,
        StreamBox::TxRx(_) => panic!("expected IO stream"),
    }
}

async fn echo(io: &mut aggligator::io::IoBox, data: &[u8]) {
    io.write_all(data).await.unwrap();
    let mut buf = vec![0; data.len()];
    io.read_exact(&mut buf).await.unwrap();
    assert_eq!(buf, data);
}

async fn wait_until(cond: impl Fn() -> bool) {
    timeout(Duration::from_secs(10), async {
        while !cond() {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("condition not reached");
}

#[tokio::test]
async fn exclusive_uses_one_connection_per_link() {
    let server = FakeServer::start().await;
    let connector = server.connector(SessionPolicy::Exclusive);
    let tag = server.tag();

    let mut a = into_io(connector.connect(&tag).await.unwrap());
    let other = connector.clone();
    let mut b = into_io(other.connect(&tag).await.unwrap());
    echo(&mut a, b"first").await;
    echo(&mut b, b"second").await;
    assert_eq!(server.connections(), 2);

    drop(a);
    wait_until(|| server.closed() == 1).await;
    echo(&mut b, b"still here").await;
}

#[tokio::test]
async fn session_cap_shares_connection_between_clones() {
    let server = FakeServer::start().await;
    let policy =
        SessionPolicy::SessionCap { max_sessions: NonZeroUsize::new(1).unwrap(), reuse: ReuseCfg::default() };
    let connector = server.connector(policy);
    let tag = server.tag();

    let other = connector.clone();
    let (a, b) = tokio::join!(connector.connect(&tag), other.connect(&tag));
    let (mut a, mut b) = (into_io(a.unwrap()), into_io(b.unwrap()));
    echo(&mut a, b"first").await;
    echo(&mut b, b"second").await;
    assert_eq!(server.connections(), 1);
    assert_eq!(server.stats.max_stream_id.load(AtomicOrdering::SeqCst), 2);

    drop(a);
    sleep(Duration::from_millis(100)).await;
    echo(&mut b, b"still here").await;
    assert_eq!(server.closed(), 0);
}

#[tokio::test]
async fn idle_session_is_closed_after_timeout() {
    let server = FakeServer::start().await;
    let reuse = ReuseCfg {
        idle_check_interval: Duration::from_millis(50),
        idle_timeout: Duration::from_millis(100),
        ..Default::default()
    };
    let connector =
        server.connector(SessionPolicy::StreamCap { max_streams: NonZeroUsize::new(4).unwrap(), reuse });
    let tag = server.tag();

    let mut a = into_io(connector.connect(&tag).await.unwrap());
    echo(&mut a, b"ping").await;
    drop(a);

    wait_until(|| server.closed() == 1).await;

    let mut b = into_io(connector.connect(&tag).await.unwrap());
    echo(&mut b, b"again").await;
    assert_eq!(server.connections(), 2);
}
