use super::*;
use rustls::RootCertStore;

fn tls() -> Arc<ClientConfig> {
    Arc::new(ClientConfig::builder().with_root_certificates(RootCertStore::empty()).with_no_client_auth())
}

fn target() -> AnyTlsTarget {
    AnyTlsTarget::Domain("acceptor.example".into(), 5800)
}

fn connector(servers: &[&str], cfg: AnyTlsCfg) -> AnyTlsConnector {
    AnyTlsConnector::new(servers, target(), "secret", tls(), cfg).unwrap()
}

fn reuse_cfg() -> AnyTlsCfg {
    AnyTlsCfg {
        policy: SessionPolicy::SessionCap {
            max_sessions: NonZeroUsize::new(1).unwrap(),
            reuse: ReuseCfg::default(),
        },
        ..Default::default()
    }
}

#[test]
fn rejects_invalid_configuration() {
    let err =
        AnyTlsConnector::new(Vec::<String>::new(), target(), "secret", tls(), AnyTlsCfg::default()).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidInput);

    let cfg = AnyTlsCfg {
        policy: SessionPolicy::StreamCap {
            max_streams: NonZeroUsize::new(2).unwrap(),
            reuse: ReuseCfg { idle_check_interval: Duration::ZERO, ..Default::default() },
        },
        ..Default::default()
    };
    let err = AnyTlsConnector::new(["127.0.0.1"], target(), "secret", tls(), cfg).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidInput);

    for host in [String::new(), "a".repeat(256)] {
        let target = AnyTlsTarget::Domain(host, 5800);
        let err = AnyTlsConnector::new(["127.0.0.1"], target, "secret", tls(), AnyTlsCfg::default()).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidInput);
    }
    let target = AnyTlsTarget::Domain("a".repeat(255), 5800);
    AnyTlsConnector::new(["127.0.0.1"], target, "secret", tls(), AnyTlsCfg::default()).unwrap();
}

#[test]
fn adds_default_server_port() {
    let connector = connector(&["127.0.0.1", "server.example", "[::1]:8443"], AnyTlsCfg::default());
    assert_eq!(connector.state.servers, ["127.0.0.1:443", "server.example:443", "[::1]:8443"]);
}

#[tokio::test]
async fn clones_share_pools_and_padding() {
    let a = connector(&["127.0.0.1"], reuse_cfg());
    let b = a.clone();
    let server = SocketAddr::from(([127, 0, 0, 1], 443));
    let other = SocketAddr::from(([127, 0, 0, 2], 443));
    let reuse = ReuseCfg::default();

    assert!(Arc::ptr_eq(&a.pool(server, &reuse), &b.pool(server, &reuse)));
    assert!(!Arc::ptr_eq(&a.pool(server, &reuse), &b.pool(other, &reuse)));
    assert!(Arc::ptr_eq(&a.padding_slot(server), &b.padding_slot(server)));
    assert!(!Arc::ptr_eq(&a.padding_slot(server), &b.padding_slot(other)));
    assert_eq!(a.padding_md5(server), "75cff2ad89aadf5e257059ee571ebe11");
}

#[tokio::test]
async fn publishes_one_link_for_each_server_address() {
    let servers = ["127.0.0.1:443", "127.0.0.2:8443", "127.0.0.1"];
    let connector = connector(&servers, AnyTlsCfg::default());
    assert_eq!(ConnectingTransport::name(&connector), NAME);

    let (tx, mut rx) = watch::channel(HashSet::new());
    let task = tokio::spawn({
        let connector = connector.clone();
        async move { connector.link_tags(tx).await }
    });

    rx.changed().await.unwrap();
    let tags = rx.borrow().clone();
    assert_eq!(tags.len(), 2);
    for server in [SocketAddr::from(([127, 0, 0, 1], 443)), SocketAddr::from(([127, 0, 0, 2], 8443))] {
        let tag: LinkTagBox = Box::new(AnyTlsLinkTag::new(server, target()));
        assert!(tags.contains(&tag));
        assert_eq!(tag.transport_name(), NAME);
        assert_eq!(tag.user_data(), server.to_string().into_bytes());
    }

    task.abort();
}

#[tokio::test]
async fn server_name_follows_configuration() {
    let localhost = ServerName::try_from("localhost").unwrap();
    let loopback = SocketAddr::from(([127, 0, 0, 1], 443));
    let ip_server = SocketAddr::from(([127, 0, 0, 2], 443));

    let connector = connector(&["localhost", "127.0.0.2"], AnyTlsCfg::default());
    let tags = connector.resolve().await;
    let tag = |addr| tags.iter().find(|tag| tag.server == addr).unwrap();
    assert_eq!(connector.server_name(tag(ip_server)), ServerName::from(ip_server.ip()));
    assert_eq!(connector.server_name(tag(loopback)), localhost);

    // An address resolved from several servers takes the name of the first one.
    let connector = self::connector(&["127.0.0.1", "localhost"], AnyTlsCfg::default());
    let tags = connector.resolve().await;
    let tag = tags.iter().find(|tag| tag.server == loopback).unwrap();
    assert_eq!(tag.server_name, None);
    assert_eq!(connector.server_name(tag), ServerName::from(loopback.ip()));

    let sni = ServerName::try_from("sni.example").unwrap();
    let connector =
        self::connector(&["localhost"], AnyTlsCfg { server_name: Some(sni.clone()), ..Default::default() });
    let tags = connector.resolve().await;
    assert!(tags.iter().all(|tag| connector.server_name(tag) == sni));
}

#[test]
fn server_name_is_not_part_of_tag_identity() {
    let server = SocketAddr::from(([127, 0, 0, 1], 443));
    let plain = AnyTlsLinkTag::new(server, target());
    let named = AnyTlsLinkTag { server_name: Some(ServerName::try_from("localhost").unwrap()), ..plain.clone() };
    assert_eq!(plain, named);

    let tags: HashSet<LinkTagBox> = [Box::new(plain) as LinkTagBox, Box::new(named) as LinkTagBox].into();
    assert_eq!(tags.len(), 1);
}

mod loopback;
