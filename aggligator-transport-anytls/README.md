# Aggligator transport: AnyTLS

[![crates.io page](https://img.shields.io/crates/v/aggligator-transport-anytls)](https://crates.io/crates/aggligator-transport-anytls)
[![docs.rs page](https://docs.rs/aggligator-transport-anytls/badge.svg)](https://docs.rs/aggligator-transport-anytls)
[![Apache 2.0 license](https://img.shields.io/crates/l/aggligator-transport-anytls)](https://raw.githubusercontent.com/remoc-rs/aggligator/master/LICENSE)

This crate provides an outgoing transport through [AnyTLS] servers, such as mihomo
or anytls-go, for the [Aggligator link aggregator].

Each AnyTLS stream carries one Aggligator link. The AnyTLS server connects each stream
to the configured target, which must be an Aggligator TCP acceptor.

Each server is configured with an IP address or hostname, optionally including a port
number (default 443). Server hostnames are resolved locally and re-resolved periodically;
one link is established per resolved IP address. Target domain names are resolved by
the AnyTLS server.

By default every link uses its own TLS connection, which is closed when the link ends.
Optionally, TLS connections can be shared by the links of different Aggligator connections,
limited either by the number of TLS connections per server IP address or by the number
of links per TLS connection. Idle shared connections are closed after a timeout.

TLS connections are made with BoringSSL and send the ClientHello of Chrome 133, the same
as uTLS `HelloChrome_Auto` and mihomo with `client-fingerprint: chrome`. On CPUs without
AES hardware support, BoringSSL puts ChaCha20-Poly1305 first among the TLS 1.3 cipher suites,
which differs from Chrome's order.

Building BoringSSL requires CMake, Clang (libclang) and git; on Windows also NASM.

Not supported: accepting AnyTLS connections, UDP over TCP, ShadowTLS and Reality.

Do not wrap this transport in the Aggligator TLS wrapper; AnyTLS already uses TLS.

[AnyTLS]: https://github.com/anytls/anytls-go
[Aggligator link aggregator]: https://crates.io/crates/aggligator

## License

Aggligator is licensed under the [Apache 2.0 license].

Parts of this crate are derived from the AnyTLS client implementation of
[shoes](https://github.com/cfal/shoes), licensed under the MIT license.
See the `NOTICE` file for details.

[Apache 2.0 license]: https://github.com/remoc-rs/aggligator/blob/master/LICENSE

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in Aggligator by you, shall be licensed as Apache 2.0, without any
additional terms or conditions.
