//! Interoperability tests against a real AnyTLS server (anytls-go or mihomo).
//!
//! These tests are ignored by default. They need an AnyTLS server and a TCP echo
//! service reachable from that server, configured by environment variables:
//!
//! * `ANYTLS_SERVER` — server address, `host:port`,
//! * `ANYTLS_PASSWORD` — server password,
//! * `ANYTLS_ECHO_TARGET` — echo service as seen from the server, `host:port`,
//! * `ANYTLS_SNI` — optional TLS server name,
//! * `ANYTLS_INSECURE` — set to `1` to skip certificate verification,
//! * `ANYTLS_PADDING_MD5` — optional MD5 of a non-default padding scheme configured
//!   on the server; enables the padding update test.
//!
//! Example with anytls-go and socat:
//!
//! ```text
//! socat TCP-LISTEN:7000,fork,reuseaddr EXEC:cat &
//! anytls-server -l 127.0.0.1:8443 -p secret &
//! ANYTLS_SERVER=127.0.0.1:8443 ANYTLS_PASSWORD=secret ANYTLS_ECHO_TARGET=127.0.0.1:7000 \
//!     ANYTLS_INSECURE=1 cargo test -p aggligator-transport-anytls --test interop -- --ignored
//! ```

use aggligator::{
    io::{IoBox, StreamBox},
    transport::ConnectingTransport,
};
use aggligator_transport_anytls::{
    AnyTlsCfg, AnyTlsConnector, AnyTlsLinkTag, AnyTlsTarget, ReuseCfg, SessionPolicy, SslConnector,
    SynAckTimeoutAction, chrome_connector_builder,
};
use boring::{
    ssl::SslVerifyMode,
    x509::{X509, store::X509StoreBuilder},
};
use std::{env, net::SocketAddr, num::NonZeroUsize, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::lookup_host,
    time::{sleep, timeout},
};

struct Env {
    server: SocketAddr,
    password: String,
    target: AnyTlsTarget,
    sni: Option<String>,
    tls: SslConnector,
}

async fn env() -> Env {
    let var = |name: &str| env::var(name).unwrap_or_else(|_| panic!("set {name}"));

    let server = lookup_host(var("ANYTLS_SERVER")).await.unwrap().next().expect("cannot resolve ANYTLS_SERVER");
    let target = AnyTlsTarget::parse(&var("ANYTLS_ECHO_TARGET"), 7).unwrap();
    let sni = env::var("ANYTLS_SNI").ok();

    let mut roots = X509StoreBuilder::new().unwrap();
    for cert in webpki_root_certs::TLS_SERVER_ROOT_CERTS {
        roots.add_cert(X509::from_der(cert).unwrap()).unwrap();
    }
    let mut tls = chrome_connector_builder().unwrap();
    tls.set_cert_store(roots.build());
    if env::var("ANYTLS_INSECURE").as_deref() == Ok("1") {
        tls.set_verify(SslVerifyMode::NONE);
    }

    Env { server, password: var("ANYTLS_PASSWORD"), target, sni, tls: tls.build() }
}

impl Env {
    fn connector(&self, policy: SessionPolicy) -> AnyTlsConnector {
        let cfg = AnyTlsCfg { server_name: self.sni.clone(), policy, ..Default::default() };
        AnyTlsConnector::new(
            [self.server.to_string()],
            self.target.clone(),
            &self.password,
            self.tls.clone(),
            cfg,
        )
        .unwrap()
    }

    fn tag(&self) -> AnyTlsLinkTag {
        AnyTlsLinkTag::new(self.server, self.target.clone())
    }
}

async fn connect(connector: &AnyTlsConnector, tag: &AnyTlsLinkTag) -> IoBox {
    match timeout(Duration::from_secs(10), connector.connect(tag)).await.unwrap().unwrap() {
        StreamBox::Io(io) => io,
        StreamBox::TxRx(_) => panic!("expected IO stream"),
    }
}

async fn echo(io: &mut IoBox, data: &[u8]) {
    io.write_all(data).await.unwrap();
    let mut buf = vec![0; data.len()];
    timeout(Duration::from_secs(10), io.read_exact(&mut buf)).await.unwrap().unwrap();
    assert_eq!(buf, data);
}

fn reuse(action: SynAckTimeoutAction) -> ReuseCfg {
    ReuseCfg { synack_timeout_action: action, ..Default::default() }
}

#[tokio::test]
#[ignore = "needs an AnyTLS server, see module documentation"]
async fn exclusive_links() {
    let env = env().await;
    let connector = env.connector(SessionPolicy::Exclusive);
    let tag = env.tag();

    let mut a = connect(&connector, &tag).await;
    let mut b = connect(&connector.clone(), &tag).await;
    echo(&mut a, b"exclusive a").await;
    echo(&mut b, b"exclusive b").await;
    drop(a);
    echo(&mut b, &vec![0x5a; 256 * 1024]).await;
}

#[tokio::test]
#[ignore = "needs an AnyTLS server, see module documentation"]
async fn session_cap_reuses_session() {
    let env = env().await;
    let policy = SessionPolicy::SessionCap {
        max_sessions: NonZeroUsize::new(1).unwrap(),
        reuse: reuse(SynAckTimeoutAction::CloseSession),
    };
    let connector = env.connector(policy);
    let tag = env.tag();

    let mut a = connect(&connector, &tag).await;
    echo(&mut a, b"first stream").await;
    // Opened on the same session with stream id 2, waiting for SYNACK on version 2 servers.
    let mut b = connect(&connector.clone(), &tag).await;
    echo(&mut b, b"second stream").await;

    drop(a);
    sleep(Duration::from_millis(200)).await;
    echo(&mut b, b"after first closed").await;
}

#[tokio::test]
#[ignore = "needs an AnyTLS server, see module documentation"]
async fn stream_cap_with_close_stream() {
    let env = env().await;
    let policy = SessionPolicy::StreamCap {
        max_streams: NonZeroUsize::new(2).unwrap(),
        reuse: reuse(SynAckTimeoutAction::CloseStream),
    };
    let connector = env.connector(policy);
    let tag = env.tag();

    let mut links = Vec::new();
    for i in 0..3u8 {
        let mut io = connect(&connector, &tag).await;
        echo(&mut io, &[i; 1024]).await;
        links.push(io);
    }
    for (i, io) in links.iter_mut().enumerate() {
        echo(io, &[i as u8 + 10; 1024]).await;
    }
}

#[tokio::test]
#[ignore = "needs an AnyTLS server with a custom padding scheme, see module documentation"]
async fn padding_update_applies_to_next_session() {
    let Ok(expected_md5) = env::var("ANYTLS_PADDING_MD5") else {
        eprintln!("ANYTLS_PADDING_MD5 not set, skipping");
        return;
    };
    let env = env().await;
    let connector = env.connector(SessionPolicy::Exclusive);
    let tag = env.tag();

    let mut a = connect(&connector, &tag).await;
    echo(&mut a, b"default padding").await;

    timeout(Duration::from_secs(10), async {
        while connector.padding_md5(env.server) != expected_md5 {
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("server did not update the padding scheme");

    let mut b = connect(&connector, &tag).await;
    echo(&mut b, b"updated padding").await;
    echo(&mut a, b"old session still works").await;
}
