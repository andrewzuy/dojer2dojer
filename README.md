# p2p-tunnel

[![CI](https://github.com/andrewzuy/dojer2dojer/actions/workflows/ci.yml/badge.svg)](https://github.com/andrewzuy/dojer2dojer/actions/workflows/ci.yml)

A small Rust CLI that lets two machines behind NATs reach each other's private
TCP services — no ports to open, no relay, no account. It combines
**STUN** (address discovery), **UDP hole punching** (NAT traversal),
**QUIC/TLS 1.3** (a reliable, encrypted byte pipe over the punched UDP hole),
and a **TCP↔QUIC stream bridge** (so ordinary TCP tools like `ssh` or `nc`
work as if the two machines were on the same LAN).

```
┌────────────────────┐                            ┌────────────────────┐
│  Machine A         │                            │  Machine B         │
│                    │   STUN servers (UDP)       │                    │
│  app ──TCP──► :12345│◄─────────────────────────►│ :22 ──TCP── app    │
│   (client role)    │                            │  (server role)     │
│                    │                            │                    │
│  ┌────────────────┐│                            │┌────────────────┐ │
│  │ QUIC (quinn)   ││═══════════ punched ═══════►││ QUIC (quinn)   │ │
│  └───────▲────────┘│        UDP hole           │└───────▲────────┘ │
│          │         │                            │        │          │
│  ┌───────┴────────┐│                            │┌───────┴────────┐ │
│  │ one UDP socket ││   1. STUN  2. punch  3. QUIC handshake       │
│  │ STUN→punch→QUIC││   4. tunnel (TCP↔QUIC byte bridge)           │
│  └────────────────┘│                            │└────────────────┘ │
└────────────────────┘                            └────────────────────┘
```

The killer detail: **one UDP socket is created up front and reused for the
whole session** — STUN discovery, hole punching, and finally the QUIC
endpoint (quinn takes ownership of it). A new socket would get a new NAT
mapping and the hole would close, so reusing it is what makes the design
work.

## How it works (the full flow)

1. **STUN discovery.** A raw RFC 5389 Binding Request is sent from THE socket
   to each configured STUN server (manual implementation, no STUN crate — we
   need full control of the socket). The response's `XOR-MAPPED-ADDRESS`
   gives our public `ip:port`.
2. **Manual peer exchange.** Your public address is printed; you paste it to
   the other party (chat message, phone, whatever) and type their address
   into the prompt. (Automated signaling is a future enhancement.)
3. **UDP hole punching.** Both sides repeatedly send small UDP packets (a
   random 8-byte session nonce) to each other's public addresses every
   `punch_interval_ms` (default 500 ms) until each sees a packet *from the
   peer*, up to `punch_timeout_secs` (default 30 s). Simultaneous punches
   typically open the NAT hole within a few seconds.
4. **Deterministic role negotiation.** Both peers independently compare their
   public addresses (lower IP → QUIC *server*, higher → QUIC *client*;
   all IPv4 sorts before IPv6; same-IP edge case falls back to the port).
   The same pure function always yields opposite roles on each side, so no
   extra signaling is needed to decide who hosts the QUIC endpoint.
5. **Self-signed certificate + QUIC handshake.** A fresh ECDSA P-256
   self-signed certificate (CN `p2p-tunnel`) is generated at startup. The
   server presents it; the client accepts *any* certificate (see
   [Security model](#security-model-mvp)). Both sides log the certificate's
   SHA-256 fingerprint so the two humans can compare out-of-band if they want
   more assurance. The punched socket is handed to quinn, which performs the
   TLS 1.3 / QUIC handshake over it.
6. **TCP↔QUIC tunnel.** Client side: a local TCP listener accepts
   connections and forwards each one into a new bidirectional QUIC stream.
   Server side: each incoming QUIC stream is bridged to a TCP connection to
   the configured target (e.g. `192.168.1.50:22`). Bytes are copied in both
   directions until either side closes; EOF in one direction only shuts that
   direction down, so the other keeps flowing.

## Development status

| Phase | What | Status |
|------:|------|:-------:|
| 0 | Project skeleton (modules, deps, logging) | ✅ |
| 1 | Config system (`config.toml`, `--config`) | ✅ |
| 2 | Manual STUN client (RFC 5389, v4+v6) | ✅ |
| 3 | Public-address display + peer prompt | ✅ |
| 4 | UDP hole punching (nonce, interval, timeout) | ✅ |
| 5 | Deterministic role negotiation | ✅ |
| 6 | Runtime self-signed cert + accept-any verifier | ✅ |
| 7 | QUIC endpoint on the punched socket | ✅ |
| 8 | TCP→QUIC bridge (client side) | ✅ |
| 9 | QUIC→TCP bridge (server side) | ✅ |
| 10 | Full `main.rs` wiring, end-to-end | ✅ |
| 11 | Logging & diagnostics polish | ✅ |
| 12 | Real-world two-machine NAT testing | ⏳ in progress |

**24 unit tests pass** (`cargo test`): STUN encode/parse, punch timing/
filtering, role symmetry, cert/fingerprint/config construction, and the
tunnel bridge's copy/half-close semantics (tested with in-memory streams).
Per project decision there is deliberately **no loopback test of the QUIC
server+client path** (one machine playing both roles); the real handshake is
validated in Phase 12 between two machines on different networks. The binary
now runs the **complete end-to-end tunnel** (steps 1–7 plus the role-branched
stream bridges); Phase 12 is the remaining real-world NAT validation.

## Requirements

- Rust (edition 2024, tested with cargo 1.93)
- Outbound UDP to a STUN server (default config uses Google/Cloudflare)
- For real use: two machines whose NATs are not symmetric (see Limitations)

## Building

```sh
cargo build --release
# binary: target/release/p2p-tunnel
```

## Usage

Run on **both** machines, each with its own `config.toml`:

```sh
# defaults to ./config.toml; override with --config /path/to/config.toml
./p2p-tunnel
```

Typical session:

```text
Your public address is: 203.0.113.7:51234
Give it to the other party, then enter their public address below:
> 198.51.100.9:48821        # ← the other party's address, typed in by hand
```

After the punch succeeds the program logs the determined role
(`server`/`client`) and the certificate fingerprint, then starts the tunnel:

- **Client side** (`local_tcp_listen_port` set): `ssh -p 12345 user@127.0.0.1`
  reaches the target on the other machine.
- **Server side** (`remote_target_addr` set): incoming tunneled traffic is
  forwarded to that private address.

### Configuration reference (`config.toml`)

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `stun_servers` | `["host:port", …]` | *(required)* | STUN servers, tried in order (hostnames OK). |
| `punch_interval_ms` | `u64` | `500` | Milliseconds between outbound punch packets. |
| `punch_timeout_secs` | `u64` | `30` | Give up on hole punching after this long. |
| `local_tcp_listen_port` | `u16?` | unset | **Client side only** — local TCP port to expose through the tunnel. |
| `remote_target_addr` | `"ip:port"?` | unset | **Server side only** — private TCP target to forward to (e.g. `"192.168.1.50:22"`). |

Example pair for tunneling `ssh` to a home server:

```toml
# client laptop
local_tcp_listen_port = 12345

# home box
remote_target_addr = "192.168.1.50:22"
```

## Security model (MVP)

Read this before using it anywhere sensitive.

- **Transport encryption is real.** QUIC mandates TLS 1.3: the channel is
  confidential and integrity-protected, and handshake signatures are
  cryptographically verified (via the ring provider) even though trust is
  permissive.
- **Identity is *not* verified.** The client accepts *any* server
  certificate — no chain, no hostname. A man-in-the-middle on the path who
  can intercept the UDP flow could in principle terminate and re-wrap it.
  This is an explicit PoC trade-off, not an oversight.
- **Mitigation: fingerprint comparison.** Both sides log the SHA-256
  fingerprint of the certificate in use at startup. If you compare them
  out-of-band (same way you'd compare an SSH host key), you can detect a MITM.
- **Planned hardening:** certificate fingerprint pinning (see `plan.md`,
  Future Enhancements) — until then treat this as a tunnel between two
  *known, mutually trusted* peers, like an ad-hoc SSH setup.

## Limitations (MVP scope)

- **IPv4 only** for the punched socket (`0.0.0.0` bind) — typical home NATs
  hand out v4; IPv6 (which needs no punching at all) is a future item.
- **Simultaneous hole punching** works best against *cone* NATs. Symmetric
  NATs / CGNAT (common on mobile hotspots) will typically fail the punch
  within the timeout — a TURN relay fallback is on the roadmap.
- **One tunnel per run, manual address exchange.** No reconnect logic yet:
  if the QUIC connection drops, re-run. Multiplexing refinements and
  resilience are future work.
- **Single target / single listen port** per side (concurrent *connections*
  to that target are fully supported).

## Repository layout

```
p2p-tunnel/
├── .github/workflows/ci.yml   # CI: lint + build/test on Linux/macOS/Windows + static musl binary
├── Cargo.toml / Cargo.lock
├── config.toml                # sample configuration
├── PROGRESS.md                # implementation scratchpad — phase-by-phase state
├── README.md                  # this file
├── tests/nat-sim/             # Phase 12 helpers: fake STUN/NAT, echo target, probe client
└── src/
    ├── main.rs          # the full pipeline, one reused UDP socket
    ├── config.rs        # Config::load (serde/toml)
    ├── cli.rs           # clap CLI + peer-address prompt/parsing
    ├── stun.rs          # manual RFC 5389 client (encode/parse/discover)
    ├── punch.rs         # hole punching loop
    ├── role.rs          # deterministic server/client decision
    ├── quic.rs          # certs, verifier, endpoint, connect/accept
    └── tunnel.rs        # TCP↔QUIC bridges (Phases 8/9)
```

The full development plan lives in `../plan.md` (repo parent); `PROGRESS.md`
tracks what is done and what the next phase needs.

## Development

```sh
cargo build     # compile
cargo test      # 24 unit tests
cargo clippy    # lint (clean with -D warnings)
cargo fmt --all -- --check   # formatting
cargo run -- --verbose   # verbose diagnostics (or RUST_LOG=debug)
```

## Continuous integration

`.github/workflows/ci.yml` runs on every push/PR to `main` (and on demand):

- **lint** (Linux) — `cargo fmt --check` + `cargo clippy --all-targets -- -D warnings`
- **build + test** — release build and full test suite on a
  Linux / macOS / Windows matrix (`fail-fast: false`, so one platform failing
  doesn't mask the others)
- **linux-static** — `x86_64-unknown-linux-musl` release build, uploaded as a
  workflow artifact (`p2p-tunnel-x86_64-linux-musl`) — a fully static binary
  that runs on minimal Linux boxes with no shared-library surprises

## License

MIT — see `LICENSE`.
