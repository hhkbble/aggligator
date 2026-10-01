#![warn(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/remoc-rs/aggligator/master/.misc/aggligator.png",
    html_favicon_url = "https://raw.githubusercontent.com/remoc-rs/aggligator/master/.misc/aggligator.png",
    issue_tracker_base_url = "https://github.com/remoc-rs/aggligator/issues/"
)]

//! [Aggligator](aggligator) transport through AnyTLS servers.
//!
//! [`AnyTlsConnector`] establishes outgoing links through AnyTLS servers, such as
//! mihomo or anytls-go. Each AnyTLS stream carries one Aggligator link; the server
//! connects each stream to the configured [target](AnyTlsTarget), which must be
//! an Aggligator TCP acceptor.
//!
//! Server hostnames are resolved locally and re-resolved periodically; one link is
//! established per resolved IP address. Each server IP address has its own sessions.
//!
//! The [`SessionPolicy`] determines whether a TLS connection carries one link only
//! ([`SessionPolicy::Exclusive`], the default) or is reused by links of other
//! Aggligator connections.
//!
//! Only the client side of the protocol is implemented. UDP over TCP is not supported.

use aggligator::{
    control::Direction,
    io::StreamBox,
    transport::{ConnectingTransport, LinkTag, LinkTagBox},
};
use async_trait::async_trait;
use std::{
    any::Any,
    cmp::Ordering,
    collections::{BTreeMap, HashMap, HashSet},
    fmt,
    hash::{Hash, Hasher},
    io::{Error, ErrorKind, Result},
    net::{IpAddr, SocketAddr},
    num::NonZeroUsize,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    net::{TcpStream, lookup_host},
    sync::watch,
    time::sleep,
};
use tokio_rustls::TlsConnector;

mod addr;
mod frame;
mod padding;
mod pool;
mod session;
mod stream;

pub use addr::AnyTlsTarget;
pub use padding::DEFAULT_PADDING_SCHEME;
#[doc(no_inline)]
pub use rustls::{ClientConfig, pki_types::ServerName};

use addr::{host_part, with_default_port};
use padding::PaddingSlot;
use pool::{Cap, EntryState, Placement, Pool, PoolSession};
use session::{Session, password_hash};

static NAME: &str = "anytls";

/// Port used when a server is specified without a port number.
pub const DEFAULT_SERVER_PORT: u16 = 443;

/// Action when the server does not acknowledge a stream in time.
///
/// Applies to streams with id 2 or higher on sessions whose server reported
/// protocol version 2; these wait 3 seconds for `cmdSYNACK`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum SynAckTimeoutAction {
    /// Fail only the stream being opened; other streams of the session continue.
    CloseStream,
    /// Close the whole session, failing all of its streams.
    #[default]
    CloseSession,
}

/// Configuration of the session policies that reuse sessions.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ReuseCfg {
    /// Interval between scans for idle sessions.
    pub idle_check_interval: Duration,
    /// A session without streams for longer than this is closed.
    pub idle_timeout: Duration,
    /// Number of idle sessions kept open even after their idle timeout.
    pub min_idle: usize,
    /// Action when a stream is not acknowledged in time.
    pub synack_timeout_action: SynAckTimeoutAction,
}

impl Default for ReuseCfg {
    fn default() -> Self {
        Self {
            idle_check_interval: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(30),
            min_idle: 0,
            synack_timeout_action: SynAckTimeoutAction::default(),
        }
    }
}

/// How links are placed onto sessions (TLS connections) to one server IP address.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub enum SessionPolicy {
    /// Each link gets its own TLS connection, which is closed when the link ends.
    #[default]
    Exclusive,
    /// At most `max_sessions` TLS connections per server IP address.
    ///
    /// New sessions are created until the limit is reached; then a new link
    /// is placed on the session with the fewest streams.
    SessionCap {
        /// Maximum number of sessions per server IP address.
        max_sessions: NonZeroUsize,
        /// Session reuse configuration.
        reuse: ReuseCfg,
    },
    /// At most `max_streams` streams per TLS connection.
    ///
    /// A new link is placed on the session with the fewest streams that has room;
    /// if none has room, a new session is created. The number of sessions is not limited.
    StreamCap {
        /// Maximum number of streams per session.
        max_streams: NonZeroUsize,
        /// Session reuse configuration.
        reuse: ReuseCfg,
    },
}

impl SessionPolicy {
    fn reuse(&self) -> Option<(Cap, &ReuseCfg)> {
        match self {
            Self::Exclusive => None,
            Self::SessionCap { max_sessions, reuse } => Some((Cap::Sessions(max_sessions.get()), reuse)),
            Self::StreamCap { max_streams, reuse } => Some((Cap::Streams(max_streams.get()), reuse)),
        }
    }
}

/// AnyTLS connector configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnyTlsCfg {
    /// TLS server name used for all servers.
    ///
    /// If unset, the configured server hostname is used, or the server IP address
    /// if the server was specified by IP address.
    pub server_name: Option<ServerName<'static>>,
    /// Session policy.
    pub policy: SessionPolicy,
    /// Interval for re-resolving the server hostnames.
    pub resolve_interval: Duration,
}

impl Default for AnyTlsCfg {
    fn default() -> Self {
        Self { server_name: None, policy: SessionPolicy::default(), resolve_interval: Duration::from_secs(10) }
    }
}

/// Link tag for an outgoing AnyTLS link.
///
/// Tags are identified by server address and target only; the TLS server name
/// does not take part in comparison or hashing.
#[derive(Debug, Clone)]
pub struct AnyTlsLinkTag {
    /// AnyTLS server address.
    pub server: SocketAddr,
    /// Target address reached through the server.
    pub target: AnyTlsTarget,
    /// TLS server name, if the server address was resolved from a hostname.
    ///
    /// [`AnyTlsCfg::server_name`] takes precedence; without either, the server IP address is used.
    pub server_name: Option<ServerName<'static>>,
}

impl AnyTlsLinkTag {
    /// Creates a link tag for an AnyTLS server and target.
    pub fn new(server: SocketAddr, target: AnyTlsTarget) -> Self {
        Self { server, target, server_name: None }
    }

    fn key(&self) -> (&SocketAddr, &AnyTlsTarget) {
        (&self.server, &self.target)
    }
}

impl PartialEq for AnyTlsLinkTag {
    fn eq(&self, other: &Self) -> bool {
        self.key() == other.key()
    }
}

impl Eq for AnyTlsLinkTag {}

impl PartialOrd for AnyTlsLinkTag {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for AnyTlsLinkTag {
    fn cmp(&self, other: &Self) -> Ordering {
        self.key().cmp(&other.key())
    }
}

impl Hash for AnyTlsLinkTag {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.key().hash(state)
    }
}

impl fmt::Display for AnyTlsLinkTag {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} -> {}", self.server, self.target)
    }
}

impl LinkTag for AnyTlsLinkTag {
    fn transport_name(&self) -> &str {
        NAME
    }

    fn direction(&self) -> Direction {
        Direction::Outgoing
    }

    fn user_data(&self) -> Vec<u8> {
        self.server.to_string().into_bytes()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn box_clone(&self) -> LinkTagBox {
        Box::new(self.clone())
    }

    fn dyn_cmp(&self, other: &dyn LinkTag) -> Ordering {
        let other = other.as_any().downcast_ref::<Self>().unwrap();
        Ord::cmp(self, other)
    }

    fn dyn_hash(&self, mut state: &mut dyn Hasher) {
        Hash::hash(self, &mut state)
    }
}

/// AnyTLS transport for outgoing connections.
///
/// Clones share sessions, session pools and padding schemes. Add clones of one
/// connector to the connectors of all Aggligator connections that should share sessions.
#[derive(Clone)]
pub struct AnyTlsConnector {
    state: Arc<State>,
}

struct State {
    servers: Vec<String>,
    target: AnyTlsTarget,
    password_hash: [u8; 32],
    tls: TlsConnector,
    cfg: AnyTlsCfg,
    pools: Mutex<HashMap<SocketAddr, Arc<Pool<Session>>>>,
    padding: Mutex<HashMap<SocketAddr, Arc<PaddingSlot>>>,
}

impl fmt::Debug for AnyTlsConnector {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("AnyTlsConnector")
            .field("servers", &self.state.servers)
            .field("target", &self.state.target)
            .field("cfg", &self.state.cfg)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for AnyTlsConnector {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let servers = &self.state.servers;
        if servers.len() > 1 {
            write!(f, "[{}] -> {}", servers.join(", "), self.state.target)
        } else {
            write!(f, "{} -> {}", servers[0], self.state.target)
        }
    }
}

impl AnyTlsConnector {
    /// Creates an AnyTLS transport to a target through one or more AnyTLS servers.
    ///
    /// `servers` can contain IP addresses and hostnames, including port numbers.
    /// If an entry does not specify a port number, [`DEFAULT_SERVER_PORT`] is used.
    /// Server hostnames are resolved locally and one link is established for each
    /// resolved IP address. Resolution is retried periodically.
    ///
    /// `target` is the Aggligator TCP acceptor the servers should connect to.
    /// `tls` is used to establish TLS connections to the servers.
    ///
    /// It is *not* checked at creation that the servers can be resolved.
    pub fn new(
        servers: impl IntoIterator<Item = impl AsRef<str>>, target: AnyTlsTarget, password: &str,
        tls: Arc<ClientConfig>, cfg: AnyTlsCfg,
    ) -> Result<Self> {
        let servers: Vec<_> =
            servers.into_iter().map(|server| with_default_port(server.as_ref(), DEFAULT_SERVER_PORT)).collect();
        if servers.is_empty() {
            return Err(Error::new(ErrorKind::InvalidInput, "at least one AnyTLS server is required"));
        }
        target.validate()?;
        if cfg.resolve_interval.is_zero() {
            return Err(Error::new(ErrorKind::InvalidInput, "resolve interval must not be zero"));
        }
        if let Some((_, reuse)) = cfg.policy.reuse()
            && reuse.idle_check_interval.is_zero()
        {
            return Err(Error::new(ErrorKind::InvalidInput, "idle check interval must not be zero"));
        }

        Ok(Self {
            state: Arc::new(State {
                servers,
                target,
                password_hash: password_hash(password),
                tls: TlsConnector::from(tls),
                cfg,
                pools: Mutex::new(HashMap::new()),
                padding: Mutex::new(HashMap::new()),
            }),
        })
    }

    /// Session policy.
    pub fn policy(&self) -> &SessionPolicy {
        &self.state.cfg.policy
    }

    /// MD5 of the padding scheme that new sessions to `server` will use.
    #[doc(hidden)]
    pub fn padding_md5(&self, server: SocketAddr) -> String {
        self.padding_slot(server).load().md5().to_string()
    }

    /// Resolves the servers to link tags, one per socket address.
    ///
    /// An address resolved from several servers takes the TLS server name of the
    /// first one in configuration order.
    async fn resolve(&self) -> Vec<AnyTlsLinkTag> {
        let mut tags = BTreeMap::new();

        for server in &self.state.servers {
            match lookup_host(server).await {
                Ok(addrs) => {
                    let host = host_part(server);
                    let server_name = match host.parse::<IpAddr>() {
                        Ok(_) => None,
                        Err(_) => ServerName::try_from(host.to_string()).ok(),
                    };
                    for addr in addrs {
                        tags.entry(addr).or_insert_with(|| AnyTlsLinkTag {
                            server: addr,
                            target: self.state.target.clone(),
                            server_name: server_name.clone(),
                        });
                    }
                }
                Err(err) => tracing::warn!(%server, %err, "cannot resolve AnyTLS server"),
            }
        }

        tags.into_values().collect()
    }

    fn server_name(&self, tag: &AnyTlsLinkTag) -> ServerName<'static> {
        self.state
            .cfg
            .server_name
            .clone()
            .or_else(|| tag.server_name.clone())
            .unwrap_or_else(|| ServerName::from(tag.server.ip()))
    }

    fn padding_slot(&self, server: SocketAddr) -> Arc<PaddingSlot> {
        self.state.padding.lock().unwrap().entry(server).or_default().clone()
    }

    /// Session pool for `server`, starting its idle scan when it is created.
    fn pool(&self, server: SocketAddr, reuse: &ReuseCfg) -> Arc<Pool<Session>> {
        let mut pools = self.state.pools.lock().unwrap();
        pools
            .entry(server)
            .or_insert_with(|| {
                let pool = Pool::<Session>::new();
                let weak = Arc::downgrade(&pool);
                let reuse = reuse.clone();
                tokio::spawn(async move {
                    loop {
                        sleep(reuse.idle_check_interval).await;
                        let Some(pool) = weak.upgrade() else { break };
                        for session in pool.scan(reuse.idle_timeout, reuse.min_idle) {
                            tracing::debug!(%server, "closing idle AnyTLS session");
                            session.terminate();
                        }
                    }
                });
                pool
            })
            .clone()
    }

    /// Establishes a TLS connection to the server of `tag` and starts a session on it.
    async fn dial(&self, tag: &AnyTlsLinkTag, exclusive: bool) -> Result<Arc<Session>> {
        let tcp = TcpStream::connect(tag.server).await?;
        let _ = tcp.set_nodelay(true);
        let tls = self.state.tls.connect(self.server_name(tag), tcp).await?;
        Session::start(tls, &self.state.password_hash, self.padding_slot(tag.server), exclusive).await
    }

    async fn connect_exclusive(&self, tag: &AnyTlsLinkTag) -> Result<StreamBox> {
        let session = self.dial(tag, true).await?;
        match session.open_stream(1, &self.state.target, None, SynAckTimeoutAction::CloseSession).await {
            Ok(io) => Ok(io.into()),
            Err(err) => {
                session.terminate();
                Err(err)
            }
        }
    }

    async fn connect_reuse(&self, tag: &AnyTlsLinkTag, cap: Cap, reuse: &ReuseCfg) -> Result<StreamBox> {
        let target = &self.state.target;
        let action = reuse.synack_timeout_action;

        match self.pool(tag.server, reuse).place(cap) {
            Placement::Dial { dial, reservation } => {
                let session = self.dial(tag, false).await?;
                match session.open_stream(1, target, Some(Box::new(reservation)), action).await {
                    Ok(io) => {
                        dial.established(session);
                        Ok(io.into())
                    }
                    Err(err) => {
                        session.terminate();
                        Err(err)
                    }
                }
            }
            Placement::Wait { stream_id, mut state, reservation } => {
                let state =
                    state.wait_for(|state| !matches!(state, EntryState::Handshaking)).await.map(|s| s.clone());
                match state {
                    Ok(EntryState::Ready(session)) => Ok(session
                        .open_stream(stream_id, target, Some(Box::new(reservation)), action)
                        .await?
                        .into()),
                    _ => Err(Error::new(ErrorKind::ConnectionAborted, "AnyTLS session failed during handshake")),
                }
            }
            Placement::Open { stream_id, session, reservation } => {
                Ok(session.open_stream(stream_id, target, Some(Box::new(reservation)), action).await?.into())
            }
        }
    }
}

#[async_trait]
impl ConnectingTransport for AnyTlsConnector {
    fn name(&self) -> &str {
        NAME
    }

    async fn link_tags(&self, tx: watch::Sender<HashSet<LinkTagBox>>) -> Result<()> {
        loop {
            let tags = self.resolve().await.into_iter().map(|tag| Box::new(tag) as LinkTagBox).collect();
            tx.send_replace(tags);

            sleep(self.state.cfg.resolve_interval).await;
        }
    }

    async fn connect(&self, tag: &dyn LinkTag) -> Result<StreamBox> {
        let tag: &AnyTlsLinkTag = tag.as_any().downcast_ref().unwrap();
        match self.state.cfg.policy.reuse() {
            None => self.connect_exclusive(tag).await,
            Some((cap, reuse)) => self.connect_reuse(tag, cap, reuse).await,
        }
    }
}

#[cfg(test)]
mod tests;
