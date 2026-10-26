# PROGRESS — implementation scratchpad (context handoff doc)

Project: `p2p-tunnel/` (Rust, edition 2024, cargo 1.93)
Plan: `../plan.md`. After each phase: verify (`cargo build` + `cargo test` + `cargo clippy`),
then update this file. Implement phases self-contained from plan.md + this file + code on disk.

## Done

### Phase 0 — Project Skeleton ✅
- Modules: main, config, stun, punch, role, quic, tunnel, cli.
- Deps: tokio(full), clap(derive), serde(derive), toml, tracing, tracing-subscriber(env-filter),
  anyhow, thiserror, rand 0.9.
- Added in Phase 6/7: quinn 0.11, rcgen 0.13, sha2 0.10, hex 0.4 (quinn re-exports rustls).
- main: `#[tokio::main]`, tracing with RUST_LOG (default `info`).
- main owns THE socket: `UdpSocket::bind("0.0.0.0:0")` (v4 MVP) — reused STUN → punch → QUIC.

### Phase 1 — Configuration System ✅
- `config::Config` (serde): `stun_servers: Vec<String>`, `punch_interval_ms: u64` (def 500),
  `punch_timeout_secs: u64` (def 30), `local_tcp_listen_port: Option<u16>`, `remote_target_addr: Option<String>`.
- `Config::load(&Path) -> anyhow::Result<Config>`; bails if stun_servers empty.
- `cli::Cli` (clap derive): `--config` default `./config.toml`. `Cli::parse()` is the clap TRAIT
  method — `use clap::Parser;` needed at call site.
- `cli::parse_peer_addr(&str) -> Result<SocketAddr, String>`.
- Sample `config.toml` in project root.

### Phase 2 — STUN Client ✅ (manual, RFC 5389)
- `stun::StunError` (thiserror): Rejected / Malformed / Io.
- `encode_binding_request(&[u8;12]) -> [u8;20]`; `parse_binding_response(&[u8], &txn) -> Result<SocketAddr, StunError>`
  (type/magic/txn checks, attr walk w/ 4-byte padding, XOR-MAPPED + MAPPED, v4+v6).
- `discover_public_addr(&UdpSocket, &[String]) -> anyhow::Result<SocketAddr>`:
  `tokio::net::lookup_host` for hostnames (config servers ARE hostnames), 2 rounds, 3s/attempt timeout.
- Verified LIVE: STUN IP == ipify == ifconfig.me (178.125.248.230).

### Phase 3 — Display Address + Manual Peer Input ✅
- `cli::prompt_peer_addr() -> anyhow::Result<SocketAddr>`: loop, stdout prompt (flush), stdin read_line,
  empty → re-prompt, invalid → eprintln reason + re-prompt. Blocking stdin in async main: OK (one-shot, documented).
- main: prints "Your public address is: X" + instructions, prompts peer.
- Verified: piped `not-an-addr\n\n1.2.3.4:9999` → 2 re-prompts then accepted.

### Phase 4 — UDP Hole Punching ✅
- `punch::punch(&UdpSocket, peer: SocketAddr, &Config) -> anyhow::Result<()>`:
  8-byte random nonce, single-task `tokio::select!` over {interval tick (first completes immediately → instant first punch),
  recv_from (accept only from==peer, ignore others w/ debug log), sleep_until(deadline)}.
  Bails with count of sent packets on timeout.
- 3 loopback tests: success-after-delay, ignores-stranger-sender, timeout. 14 tests total.
- Real-NAT verification deferred to Phase 12.

### Phase 5 — Role Negotiation ✅
- `role::Role { Server, Client }` + `as_str()`.
- `role::determine_role(own, peer) -> Role`: total order via `ip_key` —
  `(family, [u8;16])`, family 4 < 6, v4 right-padded; lower IP → Server, higher → Client.
  Same-IP tie (local testing only) falls back to port.
- 5 unit tests: both v4 orderings, exhaustively opposite roles over a mixed v4/v6 set,
  v4-beats-v6, v6 numerical order, same-IP port fallback.
- main: logs `role = server|client` after punch.

### Phase 6 — Self-Signed Certificates ✅
- Deps added: quinn 0.11, rcgen 0.13, sha2 0.10, hex 0.4. quinn re-exports rustls —
  no direct rustls dep needed (`quinn::rustls::...` paths).
- `quic::CERT_CN = "p2p-tunnel"`; `quic::generate_self_signed_cert()` →
  `(Vec<CertificateDer>, PrivateKeyDer<Pkcs8>)`, fresh ECDSA P-256 per session.
- `quic::fingerprint(&CertificateDer) -> String`: SHA-256 hex; logged on both sides
  for out-of-band comparison (MVP trust model — see README §Security).
- `AcceptAnyServerCert` (custom `ServerCertVerifier`): no chain/hostname verification,
  but TLS 1.2/1.3 handshake signatures ARE verified for real via the ring provider.
  `build_client_config()` uses it; `build_server_config(certs, key)` presents our cert.

### Phase 7 — QUIC Endpoint on the Punched Socket ✅
- `quic::create_endpoint(std::net::UdpSocket, Option<ServerConfig>)` —
  `quinn::Endpoint::new` + `quinn::default_runtime()`; takes ownership of the socket
  (our tokio socket via `.into_std()` after punch; quinn runs its own I/O driver).
- `quic::connect(&Endpoint, peer_addr)` (client, SNI = CERT_CN) and
  `quic::accept(&Endpoint)` (server) — both log on success.
- main.rs now: config → socket → STUN → print addr → prompt peer → punch → role →
  cert → QUIC endpoint (+server config if Server role, +default client config if Client).
  Binary stops here — handshake + stream bridges are wired in Phases 8–10.
- **Decision (2026-10-25):** no loopback test with QUIC server + client on
  localhost (conflicts/ambiguity on one machine); the real handshake is verified
  in Phase 12 between two real machines on different networks.

## Current API surface
- `config::Config{...}`, `Config::load(&Path)`
- `cli::Cli{config}`, `Cli::parse()`, `cli::prompt_peer_addr()`, `cli::parse_peer_addr(&str)`
- `stun::{encode_binding_request, parse_binding_response, discover_public_addr, StunError, STUN_MAGIC_COOKIE}`
- `punch::punch(&UdpSocket, SocketAddr, &Config)`
- `role::{Role, determine_role}`
- `quic::{CERT_CN, generate_self_signed_cert, fingerprint, build_client_config, build_server_config,
  create_endpoint, connect, accept}`
- `tunnel::{run_client_side, run_server_side}` — TODO stubs (Phases 8/9)

## Next: Phases 8, 9, 10
Phase 8 — Client bridge (tunnel.rs `run_client_side`): bind TCP listener on
`cfg.local_tcp_listen_port`; per accepted TCP conn → `conn.open_bi()`; two copy
tasks (TCP→QUIC, QUIC→TCP) via `tokio::io::copy`; close both ends when either side
finishes/errors.
Phase 9 — Server bridge (tunnel.rs `run_server_side`): loop on `conn.accept_bi()`;
per stream → `TcpStream::connect(cfg.remote_target_addr)`; same mirrored copy
pattern; spawn a task per stream for concurrency.
Phase 10 — Wire into main.rs: after endpoint creation, `Role::Server` →
`quic::accept` then `run_server_side`; `Role::Client` → `quic::connect` then
`run_client_side`. Parse `cfg.remote_target_addr` (server role) and
`cfg.local_tcp_listen_port` (client role) with clear errors when missing. Then
Phase 11 (logging polish) + Phase 12 (real two-machine NAT test — first real
QUIC handshake validation).

## Standing decisions
- Errors: `anyhow` at boundaries, `thiserror` for module-level errors (StunError).
- THE socket: tokio `UdpSocket` bound in main; passed `&UdpSocket` to STUN/punch; later converted via
  `.into_std()` and handed to quinn (quinn owns it from then on). NOTE: dropping a quinn
  `Endpoint` closes all its connections — keep endpoints alive for the session lifetime.
- User-facing text: `println!` (stdout); diagnostics: `tracing`.
- No loopback (same-machine) tests for the QUIC server+client path; real handshake
  validated in Phase 12 on two real machines. Loopback is fine for non-QUIC units
  (STUN parse, punch logic).
- Phase 10 flow: config → STUN → print addr → prompt peer → punch → role → certs → QUIC → tunnel.
