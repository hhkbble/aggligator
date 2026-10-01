#![warn(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/remoc-rs/aggligator/master/.misc/aggligator.png",
    html_favicon_url = "https://raw.githubusercontent.com/remoc-rs/aggligator/master/.misc/aggligator.png",
    issue_tracker_base_url = "https://github.com/remoc-rs/aggligator/issues/"
)]

//! Aggligator command line utilities.

use anyhow::{Context, bail};
use rustls::{
    ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use std::{fs::File, io::BufReader, num::NonZeroUsize, path::PathBuf, sync::Arc, time::Duration};
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

use aggligator::cfg::Cfg;
use aggligator_transport_anytls::{
    AnyTlsCfg, AnyTlsConnector, AnyTlsTarget, ReuseCfg, SessionPolicy, SynAckTimeoutAction,
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

/// Accepts every TLS server certificate, for `--anytls-insecure`.
#[derive(Debug)]
struct TlsNullVerifier;

impl ServerCertVerifier for TlsNullVerifier {
    fn verify_server_cert(
        &self, _end_entity: &CertificateDer<'_>, _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>, _ocsp_response: &[u8], _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self, _message: &[u8], _cert: &CertificateDer<'_>, _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self, _message: &[u8], _cert: &CertificateDer<'_>, _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::ECDSA_SHA1_Legacy,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
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

        let server_name = match &self.anytls_sni {
            Some(sni) => Some(ServerName::try_from(sni.clone()).context("invalid AnyTLS server name")?),
            None => None,
        };
        let cfg = AnyTlsCfg { server_name, policy: self.policy()?, ..Default::default() };

        let connector = AnyTlsConnector::new(&self.anytls, target, password, Arc::new(self.tls_config()?), cfg)
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

    fn tls_config(&self) -> anyhow::Result<ClientConfig> {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        if let Some(path) = &self.anytls_root_cert {
            let file = File::open(path).context("cannot open AnyTLS root certificate file")?;
            for cert in rustls_pemfile::certs(&mut BufReader::new(file)) {
                roots.add(cert.context("cannot parse AnyTLS root certificate")?)?;
            }
        }

        let mut cfg = ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
        if self.anytls_insecure {
            cfg.dangerous().set_certificate_verifier(Arc::new(TlsNullVerifier));
        }
        Ok(cfg)
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
