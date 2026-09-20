# storj-uplink

Native Rust [Uplink](https://pkg.go.dev/storj.io/uplink) client for [Storj](https://storj.io).

**1.1.1** extends the public `storj::*` API: access grants, buckets, objects
(multi-segment upload/download), listing, copy/move, multipart, revoke, and
Object Lock. Spec: [docs/design-native-uplink.md](docs/design-native-uplink.md).

This is **not** an S3 SDK, **not** an FFI wrapper around
[`uplink-c`](https://github.com/storj/uplink-c), and **not** a drop-in for
crates.io [`uplink` 0.11.0](https://docs.rs/uplink/0.11.0/uplink/) (blocking,
`!Send`). Go is never required to build or use the crate.

Edge credential registration and linksharing are outside this crate's scope.

## Install

```toml
[dependencies]
storj = "1.1"
tokio = { version = "1", features = ["macros", "rt-multi-thread", "io-util"] }
```

Callers need their own Tokio runtime; `tokio` is not re-exported.

Git: `storj = { git = "https://github.com/BradKollmyer/storj-uplink", tag = "v1.1.1" }`.
From this workspace: `storj = { path = "crates/storj" }`.

The public API is `storj::*` only. Implementation crates (`storj-access`,
`storj-ec`, `storj-encryption`, `storj-proto`, `storj-rpc`, `storj-uplink`)
are on crates.io so Cargo can resolve them; do not depend on them directly.
`storj-test` is unpublished.

## Quick start

Parse an access grant, open a project, upload and download. Full CLI:
[`crates/storj/examples/walkthrough.rs`](crates/storj/examples/walkthrough.rs).

```rust
use storj::{Access, Project};
use tokio::io::AsyncWriteExt;

#[tokio::main]
async fn main() -> storj::Result<()> {
    let access = Access::parse(&std::env::args().nth(1).expect("grant"))?;
    let project = Project::open(&access).await?;
    project.ensure_bucket("logs").await?;

    let mut upload = project
        .upload_object("logs", "hello.txt", Default::default())
        .await?;
    upload.write_all(b"hello storj").await?;
    let _obj = upload.commit().await?;

    let mut download = project
        .download_object("logs", "hello.txt", Default::default())
        .await?;
    let mut buf = Vec::new();
    tokio::io::copy(&mut download, &mut buf).await?;
    download.close().await?;
    project.close().await?;
    Ok(())
}
```

```bash
cargo run -p storj --example walkthrough -- "$STORJ_ACCESS"
```

`commit()` is the only path that publishes an upload. Dropping `Upload` without
`commit` aborts. `poll_shutdown` does not commit.

Custom metadata is validated before upload setters, multipart commit, and metadata
updates: keys must be nonempty, and keys/values cannot contain NUL bytes. Empty
values and Unicode are accepted. Use `verify_custom_metadata(&metadata)` for
preflight validation; invalid input returns `ErrorKind::MetadataInvalid`.

## Network transports and telemetry

Configure both satellite and storage-node connections with `Config::transport`:
`Noise` (the default), `Tcp` (TLS only), `Quic` (QUIC only), or `Auto`. Auto gives QUIC a 250 ms
head start, then races TCP/TLS; a failed QUIC attempt starts TCP immediately.
DNS, TLS authentication, and fallback share the configured dial deadline.
Both transports pin the peer's Storj NodeID and present the client identity.
QUIC carries DRPC directly with the `storj` ALPN, using Quinn and TLS 1.3.

`TransportMode::Noise` selects TCP with Noise IK for storage-node uploads and
downloads when the authenticated satellite advertises a Noise key. Metadata
calls and nodes without an advertised key use TCP/TLS. Invalid keys, unsupported
protocols, or failed Noise handshakes fail the dial without a TLS downgrade.
Both advertised ciphers (ChaCha20-Poly1305 and AES-GCM, with X25519/BLAKE2b) are
supported. The DRPC INVOKE frame is sent inside the IK handshake. DRPC flushes
that frame before sending the first piece request, so the order limit and upload
chunk travel after the handshake; they are not currently coalesced into early
data as in Go. Authentication completes during I/O and shares the dial deadline.
Upload response identities require a leaf signed by the supplied CA, whose
NodeID must match the order limit, before checking the signed piece hash.
Additional response certificates must parse but need not form a complete chain,
matching Go. TLS/QUIC handshakes still require full-chain signature validation.
Connection telemetry reports `TransportKind::Noise` for these connections.

`Config::network` controls `noise_early_data`, `tcp_fast_open`, and
`background_qos` (all enabled by default). Fast Open races ordinary TCP after
250 ms only when the satellite advertises Fast Open and a debounce limit of at
least two. Each resolved address uses a fresh Noise handshake, so a stalled
address cannot prevent another from authenticating. The Fast Open and ordinary
TCP legs for one address send at most two identical copies; without advertised
suppression, that address sends one copy over ordinary TCP.
Unavailable Fast Open support allows ordinary TCP to proceed. The optional
TFO dependency is compiled only on the platforms `tokio-tfo` implements
(Windows, Linux, Android, FreeBSD, and Apple platforms); other targets,
including the other BSDs, build without it and use ordinary TCP. TCP address candidates also race
to avoid a stalled IPv6 route blocking IPv4. On Linux, background QoS requests
Lower Effort DSCP; `congestion_control` can name a kernel TCP controller. These
socket hints are best-effort. Disable `noise_early_data` for an eager, empty-payload
handshake, or select `Tcp` to force TLS. Early data is restricted to piece Upload/Download.

```rust
use storj::{Config, Telemetry, TransportMode};

let config = Config {
    transport: TransportMode::Auto,
    telemetry: Some(Telemetry::new(|event| {
        // Forward to your metrics/logging channel without blocking.
        println!("{event:?}");
    })),
    ..Default::default()
};
// Project::open_with_config(&access, config).await?;
```

Telemetry is disabled by default. The callback receives connection-attempt
events (transport, elapsed time, outcome) and one terminal event per upload,
download, or multipart part. Transfers report plaintext bytes accepted from
the writer or delivered to the reader, elapsed time from operation start,
time to the first such byte, outcome, and configured transport mode. Upload
success means commit succeeded; download success is reported on close/drop
after the requested range was consumed. The copy helpers also report source
read and destination write/flush failures. Explicit aborts and unfinished drops are cancellations.
Initialization and transfer failures report errors. No bucket names, object
keys, credentials, payloads, or error strings are included.

Transfer events also contain `diagnostics`: working time, canonical satellite
NodeID/address, OS/architecture/CPU count, expiration status, and a sanitized
error kind plus retryability. Downloads include the requested range, normalized
range, and full object size. Object size becomes available after initialization
for downloads and successful commit for uploads/parts. Unknown values remain
`None`, including size/range when download initialization fails.

Working time excludes idle gaps between completed API operations and includes
initialization, commit/abort, and pending read/write waits. An I/O operation stays
active from its first poll until it returns Ready or the transfer terminates;
the underlying `AsyncRead`/`AsyncWrite` traits cannot observe cancellation of an
individual caller-owned I/O future. It measures wall time, not CPU usage.

To reuse a TLS identity, parse a leaf-first certificate chain and its matching
unencrypted P-256 private key (PKCS#8 or SEC1 PEM) before opening the project:

```rust
use storj::{Config, TlsIdentity};

let config = Config {
    tls_identity: Some(TlsIdentity::from_pem(&chain_pem, &key_pem)?),
    ..Default::default()
};
```

The constructor validates chain signatures and the leaf/key match, returning
`ErrorKind::InvalidTlsIdentity` for invalid input. All satellite and storage-node
TLS/QUIC connections reuse that identity, including new pooled connections.
`None` retains ephemeral identity generation. Noise still generates its own
X25519 initiator key. Debug output excludes PEM material, and stored private-key
bytes are zeroized when dropped.

Callbacks run synchronously and may run concurrently; keep them fast and
nonblocking. With panic unwinding, callback panics are caught. There is no
automatic network exporter or background delivery queue.

Remote-segment downloads launch extra pieces every `download_hedge_delay`
(default 1s) while more shares are needed; piece completions do not postpone
that deadline. `Some(Duration::ZERO)` disables hedging. Speculative launches
are capped at about 20% of the required shares. `concurrent_segments`
(default 10) caps how many remote segments transfer at once.

Existing `Config` struct literals from 1.0 must add the new fields
(`tls_identity`, `transport`, `network`, `telemetry`, `download_hedge_delay`,
and `concurrent_segments`) or use `..Default::default()`. To retain the 1.0
transport policy, set `transport: TransportMode::Tcp`; the new default
selects advertised Noise. Public transport and telemetry types are defined
by `storj`; internal RPC types are not part of the facade API.

## Comparison with `uplink` 0.11.0 (FFI)

| `uplink` 0.11.0 | `storj` 1.1.1 |
|---|---|
| crate name `uplink` | crate name `storj` |
| `uplink::access::Grant` | `storj::Access` (`Access::parse`) |
| blocking `std::io` | Tokio `AsyncRead` / `AsyncWrite` |
| `Project`, `Grant`, … are `!Send + !Sync` | public handle types are `Send + Sync` |
| `Project::open` is infallible | `Project::open` returns `Result` |
| Go required at build time | Go never required to build or use |

## MSRV

Rust 1.88 (edition 2024). This matches the existing let-chain syntax and the
patched `time` dependency used by the certificate stack.

## Build notes

On aarch64 (Apple Silicon, Graviton) the pinned `aes`/`polyval` crates only use
the ARMv8 AES and PMULL instructions when built with
`--cfg aes_armv8 --cfg polyval_armv8`; without them AES-GCM runs in software
(~10x slower). This workspace sets them in `.cargo/config.toml`; downstream
builds must set the same `rustflags` (x86_64 autodetects AES-NI).

## Tests

```bash
cargo test --workspace              # contract + mock satellite (no Go / live network)
go run -C scripts .                 # Argon2 / path-HMAC / grant goldens
STORJ_INTEROP=1 cargo test -p storj --test interop -- --ignored --skip writer_reader_size_matrix
cargo test -p storj --test quic_go_interop -- --ignored # local Go QUIC listener; no grant needed
```

Object-matrix interop and `storj-sim` need a live grant (`STORJ_INTEROP_ACCESS` /
`STORJ_SIM_ACCESS`). Production-satellite smoke tests are `#[ignore]` and also
need `STORJ_LIVE=1`; they load `STORJ_ACCESS` from the environment or a `.env`
file:

```bash
STORJ_LIVE=1 cargo test -p storj --test live -- --ignored --nocapture
```

See [crates/storj/tests/README.md](crates/storj/tests/README.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Changelog: [CHANGELOG.md](CHANGELOG.md).
Code of Conduct: [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Security

Report vulnerabilities privately — see [SECURITY.md](SECURITY.md).

## License

Dual-licensed MIT OR Apache-2.0. See [LICENSE-MIT](LICENSE-MIT) and
[LICENSE-APACHE](LICENSE-APACHE).
