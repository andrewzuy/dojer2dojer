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

### Phase 8 — Client Bridge (TCP→QUIC) ✅
- `tunnel::run_client_side(conn: quinn::Connection, listen_port: u16)`:
  binds `127.0.0.1:<port>` (loopback only); per accepted TCP conn → spawn a
  bridge task on a fresh `conn.open_bi()` stream; exits when the QUIC
  connection closes (`conn.closed()`).
- `tunnel::bridge_stream(conn, tcp)`: `open_bi()` + `tcp.into_split()` +
  `bridge_halves(tcp_read, send, recv, tcp_write)` → `(bytes_up, bytes_down)`.
- `tunnel::bridge_halves(read_a, write_a, read_b, write_b)` — the reusable copy
  core: two spawned tasks, each `tokio::io::copy` until EOF then `shutdown()`
  of its write half; resolves only when BOTH directions are done.
  **Half-close propagates** (EOF on one side does not kill the other direction —
  e.g. app finishes write side, remote replies keep flowing).
  Generic over `AsyncRead/AsyncWrite + Unpin + Send`, so it is unit-tested with
  in-memory `tokio::io::duplex` pairs — no loopback QUIC (per the decision above).
- 2 new tests: both-ways byte flow with exact counts; half-close propagation
  while the other direction keeps flowing. 24 tests total.
- Note: tokio 1.54 `TcpStream::into_split` is SYNC (returns owned halves, not a
  future) and `SendStream::finish(&mut self)` / `AsyncWrite::shutdown` send the QUIC FIN.
- main.rs untouched — wiring is Phase 10 (hence the expected dead_code warnings at the time).

### Phase 9 — Server Bridge (QUIC→TCP) ✅
- `tunnel::run_server_side(conn: quinn::Connection, target_addr: SocketAddr)`:
  loop on `tokio::select!` over `conn.accept_bi()` / `conn.closed()`; each
  accepted stream spawns its own task → `TcpStream::connect(target_addr)` →
  `bridge_quic_tcp(send, recv, tcp)`. Concurrent tunneled sessions are
  independent tasks (N streams ↔ N TCP conns).
- `tunnel::bridge_quic_tcp(send, recv, tcp)`: the shared byte-bridge core
  (refactored out of Phase 8's `bridge_stream`): `tcp.into_split()` +
  `bridge_halves(tcp_read, send, recv, tcp_write)` → `(bytes_up, bytes_down)`.
- Unreachable target: warn + `send.finish()` (FIN) so the client sees EOF
  instead of hanging.
- Quinn 0.11 notes: `Connection::accept_bi()` returns
  `Result<(SendStream, RecvStream), ConnectionError>` (NO Option wrapper);
  `SendStream::finish(&mut self)` is SYNC (`Result<(), ClosedStream>`).

### Phase 10 — Full main wiring ✅
- `main.rs` after endpoint creation: `Role::Server` → parse
  `cfg.remote_target_addr` (clear error when missing/invalid) →
  `quic::accept` → `run_server_side`. `Role::Client` →
  `cfg.local_tcp_listen_port` (clear error when missing) → `quic::connect` →
  `run_client_side`. Binary now runs the complete end-to-end tunnel.

### Phase 11 — Logging + diagnostics polish ✅
- `--verbose` CLI flag (debug logging; RUST_LOG still wins if set).
- Structured `main()` (logging init + error rendering) / `run()` (flow) split.
- tracing spans: `stun`, `punch`, `quic_handshake`, `tunnel{role}`.
- `hint_for(&Error)`: actionable hint for common failure modes —
  "STUN discovery failed" (connectivity / CGNAT), "hole punching timed out"
  (stale address / symmetric NAT), "QUIC handshake" (middlebox / peer exit),
  "is required for the" (missing config option).
- Failures print `error: {e:#}` (+hint) to stderr and `process::exit(1)`.

### CI — cross-platform GitHub Actions ✅
- `.github/workflows/ci.yml` (on push/PR to main + manual dispatch), 3 jobs:
  - `lint` (ubuntu): `cargo fmt --all -- --check` + `cargo clippy --all-targets -- -D warnings`.
    (Codebase ran through `cargo fmt` for the first time to make the fmt gate green.)
  - `build-and-test`: matrix ubuntu-latest / macos-latest / windows-latest,
    `fail-fast: false`; `cargo build --release` + `cargo test` per OS.
  - `linux-static`: `x86_64-unknown-linux-musl` release build
    (needs `musl-tools musl-dev`), uploaded as artifact
    `p2p-tunnel-x86_64-linux-musl` — fully static, portable Linux binary.
- Actions: `dtolnay/rust-toolchain@stable`, `Swatinem/rust-cache@v2`,
  `actions/checkout@v4`, `actions/upload-artifact@v4`.
- Local parity check before commit: fmt clean, clippy -D warnings clean,
  24/24 tests pass.

### Release workflow — prebuilt binaries ✅
- `.github/workflows/release.yml`, triggered by a `v*` tag push, or on demand
  (*Actions → Run workflow*, enter the tag name).
- `build` job, matrix of 5 targets (one job each, `fail-fast: false`):
  - Linux x86_64 `x86_64-unknown-linux-musl` (static; `musl-tools musl-dev`)
  - Linux ARM64 `aarch64-unknown-linux-musl` (static, cross-compiled from
    ubuntu; `ring`'s C build via apt's `gcc-aarch64-linux-gnu`, wired in with
    `CC_aarch64_unknown_linux_musl` + `-C linker=aarch64-linux-gnu-gcc`)
  - macOS `aarch64-apple-darwin` (native on the arm64 runner)
  - macOS `x86_64-apple-darwin` (cross — same toolchain, no extra setup)
  - Windows `x86_64-pc-windows-msvc` (native)
- `publish` job gathers the artifacts, writes `SHA256SUMS`, uploads everything
  to the GitHub Release via `softprops/action-gh-release@v2`
  (`generate_release_notes`, `fail_on_unmatched_files`).
- Binary names: `p2p-tunnel-<tag>-<target-triple>` (`.exe` on Windows).

### Windows bug found by CI, fixed ✅
- First CI runs failed `build + test — windows-latest`: ICMP "port
  unreachable" replies to outbound UDP punch packets surface as `recv_from`
  *errors* on Windows (Linux drops them silently), and `punch()` bailed on the
  first one instead of continuing until timeout.
- Fix in `src/punch.rs`: recv errors during punching are now logged at debug
  and ignored (keep punching until timeout). `punch_times_out_without_peer`
  doubles as the cross-platform regression test; the `cargo test` step was
  restored in `ci.yml` (it had been skipped on all OSes as a workaround).

### Idle-tunnel drop fixed: QUIC keep-alive PINGs ✅
- Symptom: after the tunnel sat idle (no traffic), the connection was
  dropped. QUIC itself is fine (its 30 s idle timeout is generous), but the
  NATs on both sides drop the port *mapping* of a silent connection after
  their own idle timeout, so the next packet has nowhere to go.
- Fix: enable QUIC keep-alive. The endpoint now sends a small PING frame
  every `keep_alive_interval_secs` (default **5 s**, new config key, `0` =
  off) once the connection is established. Implemented in `src/quic.rs`
  (`transport_config_with_keep_alive`, wired into `build_client_config` /
  `build_server_config`) and driven from `src/main.rs` + `src/config.rs`.
  Enabled on **both** roles so the tunnel survives regardless of which side
  the NAT is stricter on. `keep_alive_interval` must stay below the QUIC
  idle timeout of both peers (default 30 s) — 5 s is well under.

## Current API surface
- `config::Config{...}`, `Config::load(&Path)`
- `cli::Cli{config, verbose}`, `Cli::parse()`, `cli::prompt_peer_addr()`, `cli::parse_peer_addr(&str)`
- `stun::{encode_binding_request, parse_binding_response, discover_public_addr, StunError, STUN_MAGIC_COOKIE}`
- `punch::punch(&UdpSocket, SocketAddr, &Config)`
- `role::{Role, determine_role}`
- `quic::{CERT_CN, generate_self_signed_cert, fingerprint, build_client_config, build_server_config,
  transport_config_with_keep_alive, create_endpoint, connect, accept}`
- `tunnel::{run_client_side, run_server_side, bridge_halves}` — all phases 8–10 wired in main.

## Next: Phase 12 — real two-machine NAT test (first real QUIC handshake validation)
1. Machine A (e.g. this box): server config (`remote_target_addr` = a private
   service, e.g. `127.0.0.1:2222` running a local `ssh -p 2222` listener or a
   test TCP echo server).
2. Machine B: client config (`local_tcp_listen_port`), then
   `ssh -p <port> user@127.0.0.1` from B should land on A's target.
3. Verify: STUN addrs exchanged → punch success on both sides → QUIC handshake
   (compare cert fingerprints) → bytes flow both ways → clean shutdown.
4. Local simulation option (no second machine): two network namespaces +
   `iptables` MASQUERADE to fake a NAT — available tools on this box:
   `sudo`, `ip`, `iptables`, `nft`, `python3` (uid 1000, in `wheel`).
   **Prep (uncommitted, in `tests/nat-sim/`):** three Python helpers written —
   `stun_server.py` (fake STUN in the "box" netns that returns fake public
   addrs AND programs the DNAT rule live, i.e. the NAT port mapping),
   `echo_target.py` (natA target: banner + echo), `probe_client.py` (natB
   client: send `hello\n`, expect `PONG: hello\n`, verify clean EOF).
   Remaining: the driver (netns + MASQUERADE setup, run both tunnel
   instances, tear down) and the actual run + `TESTING.md`.

## Standing decisions
- Errors: `anyhow` at boundaries, `thiserror` for module-level errors (StunError).
- THE socket: tokio `UdpSocket` bound in main; passed `&UdpSocket` to STUN/punch; later converted via
  `.into_std()` and handed to quinn (quinn owns it from then on). NOTE: dropping a quinn
  `Endpoint` closes all its connections — keep endpoints alive for the session lifetime.
- User-facing text: `println!` (stdout); diagnostics: `tracing`.
- No loopback (same-machine) tests for the QUIC server+client path; real handshake
  validated in Phase 12 on two real machines. Loopback is fine for non-QUIC units
  (STUN parse, punch logic). Bridge logic is tested via in-memory duplex streams
  instead (`tunnel::bridge_halves` is generic on purpose).
- Tunnel half-close semantics: EOF in one direction shuts down only that
  direction's write side; the other direction keeps flowing until its own EOF.
  (Two independent copy tasks, not a `select!` that kills both on first EOF —
  first-EOF-would-kill would break e.g. `echo x | ssh host cat`.)
- Phase 10 flow: config → STUN → print addr → prompt peer → punch → role → certs → QUIC → tunnel.
