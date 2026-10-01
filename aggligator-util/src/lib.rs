#![warn(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/remoc-rs/aggligator/master/.misc/aggligator.png",
    html_favicon_url = "https://raw.githubusercontent.com/remoc-rs/aggligator/master/.misc/aggligator.png",
    issue_tracker_base_url = "https://github.com/remoc-rs/aggligator/issues/"
)]

//! Aggligator command line utilities.

use anyhow::{Context, bail};
use boring::{
    ssl::SslVerifyMode,
    x509::{X509, store::X509StoreBuilder},
};
use std::{num::NonZeroUsize, path::PathBuf, time::Duration};
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

use aggligator::cfg::Cfg;
use aggligator_transport_anytls::{
    AnyTlsCfg, AnyTlsConnector, AnyTlsTarget, ReuseCfg, SessionPolicy, SslConnector, SynAckTimeoutAction,
    chrome_connector_builder,
};
use aggligator_transport_tcp::TcpLinkFilter;

/// Initializes logging for command line utilities.
pub fn init_log() {
    tracing_subscriber::registry().with(fmt::layer()).with(EnvFilter::from_default_env()).init();
    tracing_log::LogTracer::init().unwrap();
}

/// Prints the default Aggligator configuration.
pub fn print_default_cfg() {
    println!("{}", serde_json::to_string_pretty(&Cfg::default()).unwrap());
}

/// Loads an Aggligator configuration from disk or returns the default
/// configuration if the path is empty.
pub fn load_cfg(path: &Option<PathBuf>) -> anyhow::Result<Cfg> {
    match path {
        Some(path) => {
            let file = std::fs::File::open(path).context("cannot open configuration file")?;
            serde_json::from_reader(file).context("cannot parse configuration file")
        }
        None => Ok(Cfg::default()),
    }
}

/// Parse [TcpLinkFilter] option.
pub fn parse_tcp_link_filter(s: &str) -> anyhow::Result<TcpLinkFilter> {
    match s {
        "none" => Ok(TcpLinkFilter::None),
        "interface-interface" => Ok(TcpLinkFilter::InterfaceInterface),
        "interface-ip" => Ok(TcpLinkFilter::InterfaceIp),
        other => bail!("unknown TCP link filter: {other}"),
    }
}

/// AnyTLS session mode.
#[derive(clap::ValueEnum, Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum AnyTlsMode {
    /// One TLS connection per link, closed when the link ends.
    #[default]
    Exclusive,
    /// Reuse sessions; at most --anytls-max-sessions TLS connections per server IP address.
    SessionCap,
    /// Reuse sessions; at most --anytls-max-streams links per TLS connection.
    StreamCap,
}

/// Action when an AnyTLS server does not acknowledge a stream within 3 seconds.
#[derive(clap::ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnyTlsSynAckTimeout {
    /// Fail only the stream being opened.
    CloseStream,
    /// Close the whole session.
    CloseSession,
}

/// Command line options of the AnyTLS transport.
#[derive(clap::Args, Debug, Clone, Default)]
pub struct AnyTlsArgs {
    /// AnyTLS server names or IP addresses, optionally with port numbers.
    ///
    /// One link is established through each resolved server IP address.
    /// The default server port number is 443.
    #[arg(long)]
    pub anytls: Vec<String>,
    /// Target server name or IP address reached through the AnyTLS servers.
    ///
    /// Defaults to the first TCP target.
    #[arg(long)]
    pub anytls_target: Option<String>,
    /// AnyTLS password.
    #[arg(long)]
    pub anytls_password: Option<String>,
    /// TLS server name (SNI) of the AnyTLS servers.
    ///
    /// Defaults to the server name given in --anytls.
    #[arg(long)]
    pub anytls_sni: Option<String>,
    /// Do not verify the TLS certificates of the AnyTLS servers.
    #[arg(long)]
    pub anytls_insecure: bool,
    /// PEM file with additional root certificates for verifying AnyTLS servers.
    #[arg(long)]
    pub anytls_root_cert: Option<PathBuf>,
    /// AnyTLS session mode.
    #[arg(long, value_enum, default_value_t)]
    pub anytls_mode: AnyTlsMode,
    /// Maximum number of TLS connections per AnyTLS server IP address (session-cap mode).
    #[arg(long)]
    pub anytls_max_sessions: Option<NonZeroUsize>,
    /// Maximum number of links per TLS connection (stream-cap mode).
    #[arg(long)]
    pub anytls_max_streams: Option<NonZeroUsize>,
    /// Interval in seconds for checking for idle AnyTLS sessions [default: 30].
    #[arg(long)]
    pub anytls_idle_check_interval: Option<u64>,
    /// Idle time in seconds after which an AnyTLS session is closed [default: 30].
    #[arg(long)]
    pub anytls_idle_timeout: Option<u64>,
    /// Number of idle AnyTLS sessions kept open per server IP address [default: 0].
    #[arg(long)]
    pub anytls_min_idle: Option<usize>,
    /// Action when an AnyTLS server does not acknowledge a stream in time [default: close-session].
    #[arg(long, value_enum)]
    pub anytls_synack_timeout: Option<AnyTlsSynAckTimeout>,
}

impl AnyTlsArgs {
    /// Whether AnyTLS servers were specified.
    pub fn is_enabled(&self) -> bool {
        !self.anytls.is_empty()
    }

    /// Creates the AnyTLS connector, if AnyTLS servers were specified.
    ///
    /// `default_target` is used when no AnyTLS target was specified;
    /// `target_port` is used when the target does not specify a port.
    pub fn connector(
        &self, default_target: Option<&str>, target_port: u16,
    ) -> anyhow::Result<Option<AnyTlsConnector>> {
        if !self.is_enabled() {
            return Ok(None);
        }

        let target = self
            .anytls_target
            .as_deref()
            .or(default_target)
            .context("specify the target reached through the AnyTLS servers using --anytls-target")?;
        let target = AnyTlsTarget::parse(target, target_port).context("invalid AnyTLS target")?;
        let password =
            self.anytls_password.as_deref().context("specify the AnyTLS password using --anytls-password")?;

        let cfg =
            AnyTlsCfg { server_name: self.anytls_sni.clone(), policy: self.policy()?, ..Default::default() };

        let connector = AnyTlsConnector::new(&self.anytls, target, password, self.tls_config()?, cfg)
            .context("cannot use AnyTLS servers")?;
        Ok(Some(connector))
    }

    fn policy(&self) -> anyhow::Result<SessionPolicy> {
        let reuse_given = self.anytls_idle_check_interval.is_some()
            || self.anytls_idle_timeout.is_some()
            || self.anytls_min_idle.is_some()
            || self.anytls_synack_timeout.is_some();

        let defaults = ReuseCfg::default();
        let reuse = ReuseCfg {
            idle_check_interval: self
                .anytls_idle_check_interval
                .map(Duration::from_secs)
                .unwrap_or(defaults.idle_check_interval),
            idle_timeout: self.anytls_idle_timeout.map(Duration::from_secs).unwrap_or(defaults.idle_timeout),
            min_idle: self.anytls_min_idle.unwrap_or(defaults.min_idle),
            synack_timeout_action: match self.anytls_synack_timeout {
                Some(AnyTlsSynAckTimeout::CloseStream) => SynAckTimeoutAction::CloseStream,
                Some(AnyTlsSynAckTimeout::CloseSession) => SynAckTimeoutAction::CloseSession,
                None => defaults.synack_timeout_action,
            },
        };
        if reuse.idle_check_interval.is_zero() {
            bail!("--anytls-idle-check-interval must be at least 1 second");
        }

        match self.anytls_mode {
            AnyTlsMode::Exclusive => {
                if reuse_given || self.anytls_max_sessions.is_some() || self.anytls_max_streams.is_some() {
                    bail!("AnyTLS session reuse options require --anytls-mode session-cap or stream-cap");
                }
                Ok(SessionPolicy::Exclusive)
            }
            AnyTlsMode::SessionCap => {
                if self.anytls_max_streams.is_some() {
                    bail!("--anytls-max-streams requires --anytls-mode stream-cap");
                }
                let max_sessions = self
                    .anytls_max_sessions
                    .context("--anytls-mode session-cap requires --anytls-max-sessions")?;
                Ok(SessionPolicy::SessionCap { max_sessions, reuse })
            }
            AnyTlsMode::StreamCap => {
                if self.anytls_max_sessions.is_some() {
                    bail!("--anytls-max-sessions requires --anytls-mode session-cap");
                }
                let max_streams =
                    self.anytls_max_streams.context("--anytls-mode stream-cap requires --anytls-max-streams")?;
                Ok(SessionPolicy::StreamCap { max_streams, reuse })
            }
        }
    }

    fn tls_config(&self) -> anyhow::Result<SslConnector> {
        let mut roots = X509StoreBuilder::new()?;
        for cert in webpki_root_certs::TLS_SERVER_ROOT_CERTS {
            roots.add_cert(X509::from_der(cert)?)?;
        }
        if let Some(path) = &self.anytls_root_cert {
            let pem = std::fs::read(path).context("cannot open AnyTLS root certificate file")?;
            for cert in X509::stack_from_pem(&pem).context("cannot parse AnyTLS root certificate")? {
                roots.add_cert(cert)?;
            }
        }

        let mut tls = chrome_connector_builder()?;
        tls.set_cert_store(roots.build());
        if self.anytls_insecure {
            tls.set_verify(SslVerifyMode::NONE);
        }
        Ok(tls.build())
    }
}

/// Waits for a platform-specific termination signal.
pub async fn wait_sigterm() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        let mut sigterm = signal(SignalKind::terminate()).unwrap();
        let mut sigint = signal(SignalKind::interrupt()).unwrap();
        let mut sighup = signal(SignalKind::hangup()).unwrap();

        tokio::select! {
            _ = sigterm.recv() => {},
            _ = sigint.recv() => {},
            _ = sighup.recv() => {},
        }
    }

    #[cfg(windows)]
    {
        use tokio::signal::windows;

        let mut ctrl_c = windows::ctrl_c().unwrap();
        let mut ctrl_break = windows::ctrl_break().unwrap();
        let mut ctrl_close = windows::ctrl_close().unwrap();
        let mut ctrl_logoff = windows::ctrl_logoff().unwrap();
        let mut ctrl_shutdown = windows::ctrl_shutdown().unwrap();

        tokio::select! {
            _ = ctrl_c.recv() => {},
            _ = ctrl_break.recv() => {},
            _ = ctrl_close.recv() => {},
            _ = ctrl_logoff.recv() => {},
            _ = ctrl_shutdown.recv() => {},
        }
    }

    #[cfg(not(any(unix, windows)))]
    {
        std::future::pending::<()>().await;
    }

    tracing::info!("received termination signal");
}
