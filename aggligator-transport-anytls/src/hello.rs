//! Chrome 133 ClientHello through BoringSSL.

use boring::{
    error::ErrorStack,
    ssl::{
        CertificateCompressionAlgorithm, CertificateCompressor, ConnectConfiguration, SslConnector,
        SslConnectorBuilder, SslMethod, SslSignatureAlgorithm, SslVersion,
    },
    x509::store::X509StoreBuilder,
};
use foreign_types::ForeignTypeRef;
use std::{
    io::{Result, Write},
    ptr,
};

const CURVES: &str = "X25519MLKEM768:X25519:P-256:P-384";

/// TLS 1.2 cipher suites in Chrome's order; TLS 1.3 suites are not configurable.
const TLS12_CIPHERS: &str = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:\
    ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:\
    ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:\
    ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA";

const SIGNATURE_ALGORITHMS: [SslSignatureAlgorithm; 8] = [
    SslSignatureAlgorithm::ECDSA_SECP256R1_SHA256,
    SslSignatureAlgorithm::RSA_PSS_RSAE_SHA256,
    SslSignatureAlgorithm::RSA_PKCS1_SHA256,
    SslSignatureAlgorithm::ECDSA_SECP384R1_SHA384,
    SslSignatureAlgorithm::RSA_PSS_RSAE_SHA384,
    SslSignatureAlgorithm::RSA_PKCS1_SHA384,
    SslSignatureAlgorithm::RSA_PSS_RSAE_SHA512,
    SslSignatureAlgorithm::RSA_PKCS1_SHA512,
];

/// ALPN protocols `h2` and `http/1.1` in wire format.
const ALPN: &[u8] = b"\x02h2\x08http/1.1";

/// ALPN protocol advertised with application settings (ALPS).
const ALPS_PROTOCOL: &[u8] = b"h2";

/// Decompresses brotli-compressed server certificates.
struct BrotliDecompressor;

impl CertificateCompressor for BrotliDecompressor {
    const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm::BROTLI;
    const CAN_COMPRESS: bool = false;
    const CAN_DECOMPRESS: bool = true;

    fn decompress<W: Write>(&self, mut input: &[u8], output: &mut W) -> Result<()> {
        brotli_decompressor::BrotliDecompress(&mut input, output)
    }
}

/// Creates a TLS connector builder whose connections send the ClientHello of Chrome 133.
///
/// The hello matches uTLS `HelloChrome_133`, including GREASE, extension permutation,
/// post-quantum key exchange, ALPS and ECH GREASE.
///
/// The certificate store is empty. Install trust roots with
/// [`set_cert_store`](boring::ssl::SslContextBuilder::set_cert_store), or disable
/// certificate verification with [`set_verify`](boring::ssl::SslContextBuilder::set_verify)
/// and [`SslVerifyMode::NONE`](boring::ssl::SslVerifyMode::NONE), which also disables hostname
/// verification. Do not enable a client session cache: Chrome's hello carries no `pre_shared_key`.
pub fn chrome_connector_builder() -> Result<SslConnectorBuilder> {
    let mut builder = SslConnector::builder(SslMethod::tls())?;
    builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
    builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;
    builder.set_grease_enabled(true);
    builder.set_permute_extensions(true);
    builder.set_curves_list(CURVES)?;
    builder.set_verify_algorithm_prefs(&SIGNATURE_ALGORITHMS)?;
    builder.set_strict_cipher_list(TLS12_CIPHERS)?;
    builder.set_alpn_protos(ALPN)?;
    builder.enable_ocsp_stapling();
    builder.enable_signed_cert_timestamps();
    builder.add_certificate_compression_algorithm(BrotliDecompressor)?;
    builder.set_cert_store(X509StoreBuilder::new()?.build());
    Ok(builder)
}

/// Configures one connection of `connector` with the per-connection parts of the Chrome hello.
pub(crate) fn configure(connector: &SslConnector, verify_hostname: bool) -> Result<ConnectConfiguration> {
    let mut config = connector.configure()?;

    let ssl = config.as_ptr();
    // SAFETY: `ssl` is owned by `config`; BoringSSL copies the protocol name.
    unsafe {
        boring_sys::SSL_set_alps_use_new_codepoint(ssl, 1);
        if boring_sys::SSL_add_application_settings(
            ssl,
            ALPS_PROTOCOL.as_ptr(),
            ALPS_PROTOCOL.len(),
            ptr::null(),
            0,
        ) != 1
        {
            return Err(ErrorStack::get().into());
        }
    }

    config.set_enable_ech_grease(true);
    config.set_verify_hostname(verify_hostname);
    Ok(config)
}
