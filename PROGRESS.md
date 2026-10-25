# PROGRESS — implementation scratchpad (context handoff doc)

Project: `p2p-tunnel/` (Rust, edition 2024, cargo 1.93)
Plan: `../plan.md`. After each phase: verify (`cargo build` + `cargo test` + `cargo clippy`),
then update this file. Implement phases self-contained from plan.md + this file + code on disk.

## Done

### Phase 0 — Project Skeleton ✅
- Modules: main, config, stun, punch, role, quic, tunnel, cli.
- Deps: tokio(full), clap(derive), serde(derive), toml, tracing, tracing-subscriber(env-filter),
  anyhow, thiserror, rand 0.9.
- **NOT added yet:** quinn, rustls, rcgen — add in Phase 6 (certs) / Phase 7 (quic).
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

## Current API surface
- `config::Config{...}`, `Config::load(&Path)`
- `cli::Cli{config}`, `Cli::parse()`, `cli::prompt_peer_addr()`, `cli::parse_peer_addr(&str)`
- `stun::{encode_binding_request, parse_binding_response, discover_public_addr, StunError, STUN_MAGIC_COOKIE}`
- `punch::punch(&UdpSocket, SocketAddr, &Config)`
- main flow so far: config → bind socket → STUN → print addr → prompt peer → punch → (stop).

## Notes for next phases (5 & 6 are small; 7 is the big one)
Phase 5 — Role: `role::Role { Server, Client }` (serde? no — internal only),
`determine_role(own: SocketAddr, peer: SocketAddr) -> Role`: compare `own.ip() < peer.ip()` (v4 u32;
v6 as u128; if mixed families — v4 < v6 or just bail with clear error). Ties impossible (different addrs).
Pure function, unit-test both orderings + IPv6. main: log "we will be the {server|client}".
Phase 6 — Certs: add deps quinn 0.11, rustls (matching quinn's), rcgen.
`quic::generate_self_signed() -> (Certificate, PrivateKey)`: rcgen with CN "p2p-tunnel", SAN IP 127.0.0.1
(+ maybe the local public IP we'll bind to — keep simple: 127.0.0.1 + IPAny?). Client accepts ANY cert:
`dangerous_configuration`-free way = custom rustls `ServerCertVerifier`. MVP: implement a small
`AcceptAnyServerCertVerifier` (validate expiry? no — accept all, it's a tunnel between two known peers).
Phase 7 — QUIC: quinn `Endpoint::new(endpoint_cfg, Default::default(), socket.into_std().unwrap())`
(socket.to_std() → std UdpSocket; quinn takes ownership of the std socket — note: our tokio socket must be
converted via `to_std()`; quinn manages it with its own IO. This is fine: after punching, hand the socket to quinn).
Server: `endpoint.accept()` → connection → `accept_bi` stream. Client: `endpoint.connect(server_name, addr)` —
server_name must match cert: use "p2p-tunnel" as CN and connect with that name... quinn connect requires a DNS
name for SNI; our verifier ignores it. Use CN "localhost"? We'll connect with name "p2p-tunnel" and set the
verifier to not check. Then tunnel.rs (phases 8/9) copies bytes both directions between a TCP end and the
quinn bi-stream.

## Standing decisions
- Errors: `anyhow` at boundaries, `thiserror` for module-level errors (StunError).
- THE socket: tokio `UdpSocket` bound in main; passed `&UdpSocket` to STUN/punch; later converted via
  `.to_std()` and handed to quinn (quinn owns it from then on).
- User-facing text: `println!` (stdout); diagnostics: `tracing`.
- Phase 10 flow: config → STUN → print addr → prompt peer → punch → role → certs → QUIC → tunnel.
