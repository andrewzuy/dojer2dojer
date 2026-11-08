# PLAN — Python rewrite of p2p-tunnel

Status: **active**. This branch (`python`) rewrites the Rust `p2p-tunnel` (on
`main`, frozen reference at `f2dc2a4`) in Python. `PROGRESS.md` is the
development log; the Rust implementation on `main` is the behavioral
**oracle** — where this document and the Rust code disagree, the Rust code
wins and this document must be corrected.

---

## 1. Goals

1. **Feature parity** with the Rust tool as of `main` (tip `f2dc2a4`):
   STUN discovery → address exchange (manual prompt **and** Telegram
   bot-to-bot `PTUN READY` / `PTUN v1`) → simultaneous UDP hole punching →
   deterministic role → fresh self-signed cert → QUIC/TLS 1.3 byte pipe over
   the punched socket → TCP↔QUIC stream bridge, with a live terminal UI,
   keep-alive PINGs, and actionable error hints.
2. **As few third-party dependencies as possible.** Decision (verified,
   §2): exactly **one** direct runtime dependency — `aioquic` (pure-Python
   QUIC + TLS 1.3, BSD-3; pulls `cryptography`, `h11`, `pyrfc3339`
   transitively). Everything else is the Python standard library:
   `asyncio`, `tomllib`, `argparse`, `urllib`, `ssl`, `hashlib`,
   `curses` (TUI), `unittest`, `logging`, `socket`, `threading`.
3. **Python ≥ 3.11** (need `tomllib`; 3.11–3.14 supported).
4. The wire formats and observable behaviors (logs, prompts, exit codes,
   config keys, CLI flags, TUI phases) match the Rust version, so users can
   migrate by replacing the binary.

### Non-goals (same limitations as the Rust MVP)

- IPv4 only (socket bound to `0.0.0.0:0`); IPv6 STUN parsing may exist but
  the pipeline is IPv4-first as in Rust.
- No TURN/relay fallback, no reconnect, no role override.
- One local TCP port (client side), one remote target (server side).
- MVP trust model: both sides accept the peer's fresh self-signed cert;
  humans compare the printed SHA-256 fingerprints out of band.

---

## 2. Verified foundation: the `aioquic` spike (done at branch creation)

`aioquic 1.7.2` + `cryptography 50.0.2` install cleanly on Python 3.14.
Key API facts, verified by reading the installed sources:

- **Socket reuse — the killer detail — works on BOTH roles.**
  - `aioquic.asyncio.connect()` internally does
    `loop.create_datagram_endpoint(factory, sock=its_own_sock)` after
    binding its own socket. We replicate that pattern with **our** socket:
    ```python
    configuration = QuicConfiguration(is_client=True,
                                      server_name="p2p-tunnel",
                                      verify_mode=ssl.CERT_NONE,
                                      idle_timeout=60.0)
    conn = QuicConnection(configuration=configuration)
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: QuicConnectionProtocol(conn, stream_handler=None),
        sock=our_punched_socket)
    protocol.connect((peer_ip, peer_port), transmit=True)
    await protocol.wait_connected()
    ```
  - Server side: `QuicServer` (in `aioquic.asyncio.server`) is a plain
    `asyncio.DatagramProtocol` whose `connection_made` just stores the
    transport; `serve()` merely wraps
    `loop.create_datagram_endpoint(lambda: QuicServer(...), local_addr=...)`.
    So we instantiate `QuicServer` directly and attach our socket:
    ```python
    server = QuicServer(configuration=server_cfg, stream_handler=on_stream)
    transport = await loop.create_datagram_endpoint(lambda: server,
                                                    sock=our_punched_socket)
    ```
  - Result: **the exact same OS socket used for STUN + punching carries the
    QUIC connection** — identical design to the Rust `quinn` version.
- **Streams are first-class asyncio streams.**
  `protocol.create_stream(is_unidirectional=False)` returns
  `(asyncio.StreamReader, asyncio.StreamWriter)`.
  `QuicStreamAdapter.write_eof()` sends the QUIC FIN → **half-close is
  native**, and the bridge code is byte-for-byte the same shape as Rust
  (`copy(reader_a, writer_b); copy(reader_b, writer_a)`).
- **Server-side stream delivery** is the `stream_handler(reader, writer)`
  callback passed to `QuicServer`.
- **Accept-any-cert** (client): aioquic 1.7.2 has no `is_trusted` flag;
  verification is `QuicConfiguration.verify_mode` (`ssl` constants).
  `verify_mode=None` defaults clients to `CERT_REQUIRED`; we set
  `ssl.CERT_NONE` — the Python equivalent of the Rust
  `AcceptAnyServerCert`.
- **Peer cert (nice-to-have):** after the handshake,
  `protocol.connection.tls._peer_certificate` holds the peer's
  `x509.Certificate` (private attribute — use defensively, pin the version).
  Rust logs the peer cert fingerprint on the client; Python logs its **own**
  fingerprint on both sides (same UX: humans compare two printed hashes) and
  additionally the peer's fingerprint if extraction succeeds.
- **Keep-alive:** no built-in interval. We run a task that calls
  `await protocol.ping()` every `keep_alive_interval_secs` (0 = off), on
  both roles, matching the Rust `TransportConfig.keep_alive_interval`.
  `ping()` awaits the PING ack — the task is cancelled when the connection
  closes.
- `QuicConfiguration.idle_timeout` defaults to 60 s; we set it explicitly.
- **Pin `aioquic>=1.7,<2`** in `pyproject.toml`. If a future release changes
  the internals we rely on (`QuicServer` as a plain protocol, the
  `create_datagram_endpoint(sock=...)` pattern), fallback: rebind a fresh
  socket to the *same local port* before handing it to aioquic — the
  4-tuple is identical, so the punched NAT mappings still match.

Everything else in the pipeline (STUN, punching, roles, certs, Telegram,
TUI) is pure standard library.

---

## 3. Architecture

Single `asyncio` process. The pipeline is a linear async function; the TUI is
a separate **render thread** fed by a `queue.Queue` — the same
decoupling as the Rust version (no pipeline code calls UI code; it only
emits events).

```
main()
 ├─ argparse CLI                       (cli.py)
 ├─ Config.load()                      (config.py, tomllib)
 ├─ TUI: queue + render thread         (tui.py, tui_state.py)  [or plain logging]
 ├─ udp = UdpSocket("0.0.0.0":0)       (stun.py — THE socket, bound once)
 ├─ address exchange                   (cli.py / telegram.py)
 │    manual: STUN → prompt
 │    telegram: PTUN READY → STUN → PTUN v1 → (fallback: prompt)
 ├─ punch(udp, peer_addr, cfg)         (punch.py)
 ├─ role = determine_role(own, peer)   (role.py)
 ├─ cert = generate_self_signed_cert() (quic.py)  → log fingerprint
 ├─ role==Server: QuicServer on udp, await first connection
 │  role==Client: QuicConnectionProtocol on udp, connect(peer)
 ├─ keep-alive task (both roles)       (quic.py)
 └─ bridge                             (tunnel.py)
      client: TCP listener 127.0.0.1:port → per-conn QUIC bi-stream
      server: per QUIC stream → TCP connect to remote_target_addr
```

### The one UDP socket

`socket.socket(AF_INET, SOCK_DGRAM)`, `bind(("0.0.0.0", 0))`, local port
from `getsockname()`. STUN and punch I/O uses the stdlib-sanctioned asyncio
wrappers `loop.sock_sendto(sock, ...)` / `loop.sock_recvfrom(sock, ...)`
(which manage non-blocking mode + the selector). For QUIC we hand the same
`sock` object to `loop.create_datagram_endpoint(..., sock=sock)` — asyncio
takes it over (exactly what aioquic's own `connect()` does). The pipeline is
strictly sequential, so no coroutine touches the socket during handover.

### Module map (Rust → Python)

| Rust (`main` branch) | Python | Notes |
|---|---|---|
| `src/cli.rs` | `p2p_tunnel/cli.py` | `argparse` (subcommand-free, same flags); `parse_peer_addr`; `prompt_peer_addr` loop with mode toggle / abort / EOF outcomes |
| `src/config.rs` | `p2p_tunnel/config.py` | `tomllib` (read-only TOML); same keys, same defaults, same validation |
| `src/stun.rs` | `p2p_tunnel/stun.py` | Hand-rolled RFC 5389 (byte-identical layout); `struct`/`int.to_bytes` encode; `struct.unpack` parse |
| `src/punch.rs` | `p2p_tunnel/punch.py` | Same 8-byte nonce, same interval/timeout semantics, same error text |
| `src/role.rs` | `p2p_tunnel/role.py` | Total order over `(family, octets)`; port tie-break; `Role.as_str()` |
| `src/quic.rs` | `p2p_tunnel/quic.py` | `cryptography` x509 builder for the cert (P-256, CN `p2p-tunnel`, SAN + CN, 30 days); fingerprint = `hex(sha256(DER))`; aioquic attach/connect/accept on the reused socket; keep-alive task |
| `src/tunnel.py` | `p2p_tunnel/tunnel.py` | Generic `bridge_halves` over `StreamReader`/`StreamWriter` (works for both TCP and QUIC streams — same abstraction as Rust's generic bounds) |
| `src/telegram.rs` | `p2p_tunnel/telegram.py` | `urllib.request` (blocking → `loop.run_in_executor`) or plain `http.client`; same payloads, same `getUpdates` loop, same staleness/echo rules |
| `src/tui.rs` | `p2p_tunnel/tui.py` | `curses` (stdlib) render thread; same `TuiEvent` set; inline prompt editor; `q`/Esc/Ctrl-C abort; `t` mode toggle |
| `src/tui_state.rs` | `p2p_tunnel/tui_state.py` | Direct port: `Phase`, `PhaseStatus`, `ExchangeMode`, `TuiState`, event folding |
| `src/main.rs` | `p2p_tunnel/main.py` | Pipeline orchestration, `--tui/--no-tui` auto-detect, `error:` + `hint_for()` exit-1 |
| `src/lib.rs` | `p2p_tunnel/__init__.py` | Version + docstring only (modules import flat) |
| — | `p2p_tunnel/__main__.py` | `python -m p2p_tunnel` entry |

### Error handling

- `PuntunnelError(Exception)` base + per-module subclasses
  (`StunError`, `PunchTimeout`, `TelegramError`, `QuicSetupError`, …) —
  mirrors the Rust `thiserror` enums, including the exact user-facing
  message strings (they are part of the UX and the `hint_for()` matching).
- `main()` catches, renders `error: <chain>` + hint, exits 1. Hints
  (substring match, same four as Rust):
  - `"STUN discovery failed"` → connectivity/CGNAT hint
  - `"hole punching timed out"` → address-stale / symmetric-NAT hint
  - `"QUIC handshake"` → middlebox / peer-exited hint
  - `"is required for the"` → missing config option hint
- Logging: stdlib `logging`. Plain mode → stderr, level from
  `LOG_LEVEL` env (Rust used `RUST_LOG`; we keep **both** env vars checked,
  `P2P_TUNNEL_LOG` first then `RUST_LOG` for migration), else
  `--verbose`→DEBUG else INFO. TUI mode → logging disabled (the TUI is the
  single source of truth, same as Rust).

### TUI (curses)

- `tui_state.py` is a direct, testable port (no terminal needed).
- `tui.py` owns a daemon **thread** running the curses loop on
  `curses.initscr()`, alternate screen via `curses.curs_set(0)` + the
  standard curses idiom, `nodelay` polling of the event queue, and
  `getch()` for keys. Layout mirrors Rust: header (status color), 6-phase
  stepper, connection panel (own/peer addr, role, fingerprint, local port /
  target, exchange-mode badge), bounded event-log panel, bottom prompt line
  while a prompt is active.
- Prompt handling: pipeline emits `Prompt(text)`; render thread switches to
  inline editing (keys → input line, Enter → submit, `t` → mode toggle,
  `q`/Esc/Ctrl-C → abort) and answers the pipeline's `queue.Queue` with a
  `PromptOutcome` — same contract as Rust.
- Availability: `curses` is stdlib on Linux/macOS and absent on Windows →
  TUI auto-disabled on Windows (plain logging), and `--tui` on a non-TTY
  degrades with a warning. Same "auto on when stdout is a TTY" rule as Rust.

---

## 4. Wire & behavior spec (parity contract)

### STUN (RFC 5389 subset) — `stun.py`

- Binding Request: `msg_type=0x0001`, `msg_len=0`, `magic=0x2112A442`,
  96-bit random transaction ID.
- Response parsing: `msg_type=0x0101` (0x0111 → error with code+reason),
  magic verified, transaction ID must match, ignore packets from other
  senders/ports. Attributes scanned in order; skip unknown (pad to 4).
  `ATTR_MAPPED_ADDRESS` (0x0001) and `ATTR_XOR_MAPPED_ADDRESS` (0x0020),
  IPv4 (family 0x01) and IPv6 (family 0x02); XOR per RFC 5389 §15.
- Discovery: for each configured server (default port 19302 when absent),
  up to **2 rounds**, **3 s** per attempt, 512-byte datagram buffer. First
  valid response wins; all servers exhausted → `StunError` with the last
  reason; final error text starts with `"STUN discovery failed"`.

### Address exchange

- **Manual:** after STUN, print
  `Your public address is: <ip:port>` / instruction line, then prompt
  `Enter peer's public address (ip:port): ` — accept `ip:port` or bare
  `ip` (port default 19302? No — **manual peer input requires `ip:port`**;
  bare IP is rejected: mirror Rust `parse_peer_addr` exactly: valid
  `ip:port` only, invalid → re-prompt with error message).
- **Telegram (PTUN protocol):**
  - `PTUN READY <secret>` — sent to `peer_bot_id` at startup; wait up to
    `timeout_secs` (default 120) for the peer bot's READY line with the
    **same** secret. Proves liveness before STUN.
  - `PTUN v1 <ip:port>` — after STUN, announce own address; wait for
    peer's line, parse `ip:port`.
  - Long-poll `getUpdates` every 10 s (`timeout=10`, `allowed_updates=["message"]`),
    `offset` = highest consumed `update_id` + 1.
  - Staleness: ignore lines whose `date` is older than 600 s; accept lines
    with `date == 0` (test mock) or missing.
  - Ignore own bot's echoed messages (sender id == own bot id from
    `getMe`), non-bot senders, messages from unexpected chat ids.
  - API base: default `https://api.telegram.org`, overridable via env
    `PTUN_TELEGRAM_API_BASE` (used by the mock API test).
  - HTTP: form-encoded POST `data=urlencoded` (no JSON body dependency),
    JSON responses parsed with `json` (stdlib). `ok=false` → error with
    `description`.
  - Any Telegram failure → warn + **fall back to the manual prompt**
    (Telegram is a second channel, never a blocker).

### Hole punching — `punch.py`

- One 8-byte random nonce payload; first packet sent **immediately**, then
  every `punch_interval_ms` (config default 500, floor 10 ms).
- Wait for any UDP datagram **from exactly `peer_addr`** (ignore everyone
  else, ignore ICMP-style recv errors the way the Rust version does on
  Windows). First good packet → success, log packet count + elapsed.
- No packet within `punch_timeout_secs` (default 30) → error
  `"hole punching timed out …"` including packets sent.

### Role — `role.py`

- Total order: public address tuples `(family, *octets)` compared
  numerically — IPv4 (family 4) always sorts before IPv6 (family 6);
  same family → byte-wise octet comparison; equal IP → lower **port**
  wins. The lower endpoint is **Server** (accepts QUIC + forwards to its
  `remote_target_addr`); the higher is **Client** (opens QUIC + runs the
  local TCP listener). Roles are always opposite; a perfect tie is
  impossible for two real endpoints (same IP+port = same machine).

### QUIC/TLS — `quic.py`

- Fresh self-signed cert each run: EC **P-256**, CN `p2p-tunnel` (also in
  SAN), notBefore now, notAfter +30 days. Fingerprint =
  `hex(sha256(DER))` (64 chars) — logged on both sides; humans compare
  out of band.
- Server: `QuicConfiguration(is_client=False, alpn_protocols=None,
  certificate=<x509 cert object>, private_key=<EC key>, idle_timeout=60)`.
  (aioquic accepts `cryptography` objects directly for
  `certificate`/`private_key` — set as dataclass fields, same as
  `load_cert_chain` does internally.)
- Client: `QuicConfiguration(is_client=True, server_name="p2p-tunnel",
  verify_mode=ssl.CERT_NONE, idle_timeout=60)`.
- Attach on the reused socket (§2). Keep-alive: every
  `keep_alive_interval_secs` (default 5; 0 disables), both roles, via
  `protocol.ping()` in a cancellable task.
- Handshake failures surface with `"QUIC handshake …"` in the message
  (hint matching).

### Tunnel — `tunnel.py`

- `bridge_halves(r1, w1, r2, w2)`: two copy tasks
  (`async for chunk in reader: writer.write(chunk)`), EOF →
  `writer.write_eof()`; both directions complete or either transport error
  propagates; close both sides afterwards. Generic over asyncio streams →
  identical code for TCP and QUIC.
- **Client role:** TCP listener on `127.0.0.1:<local_tcp_listen_port>`
  (loopback only — the tunnel's entry point; `localhost`-only by design).
  Each accepted TCP connection → one new QUIC bi-directional stream
  (`create_stream(False)`) → bridge. QUIC closed → listener closes;
  connection error → drop that TCP connection, keep others.
- **Server role:** each **incoming** QUIC stream (via `stream_handler`) →
  `loop.create_connection` to `remote_target_addr` → bridge. Target
  unreachable → warn + close the stream with FIN (client sees EOF), keep
  serving other streams.
- Byte counters logged per connection on close (as in Rust).

### CLI & config — `cli.py`, `config.py`

Flags (argparse): `--config PATH` (default `./config.toml`),
`--telegram` (enable bot-to-bot exchange; requires `[telegram]` table),
`--tui` / `--no-tui` (auto: TTY), `--verbose` (DEBUG logging), `-h`, `-V`.

Config (TOML, `tomllib`):

| key | type | default | notes |
|---|---|---|---|
| `stun_servers` | `list[str]` | **required, ≥1** | `host` or `host:port`, default port 19302 |
| `punch_interval_ms` | `int` | 500 | floor 10 |
| `punch_timeout_secs` | `int` | 30 | |
| `keep_alive_interval_secs` | `int` | 5 | 0 = off |
| `local_tcp_listen_port` | `int` | — | required for **client** role |
| `remote_target_addr` | `str` `ip:port` | — | required for **server** role |
| `[telegram] token` | `str` | — | bot API token |
| `[telegram] peer_bot_id` | `int` | — | peer bot's numeric id |
| `[telegram] timeout_secs` | `int` | 120 | |
| `[telegram] secret` | `str` | — | shared secret for `PTUN READY` |

Unknown keys ignored (Rust serde default behavior). Role-required keys are
validated **after** role determination (error text contains
`"is required for the"` → hint).

### TUI state machine — `tui_state.py`

Direct port: `Phase` (Stun, Exchange, Punch, Role, Quic, Tunnel),
`PhaseStatus` (Pending/Active/Done/Error), `ExchangeMode` (Manual/Telegram),
`TuiState` (phase map, own/peer addr, role, fingerprint, local_port,
target, ready/done/error flags, bounded 500-line log, tick, exchange mode,
telegram_available, active prompt). `set_phase` auto-completes an earlier
stuck Active phase. `active_phase()` reports the frontier.

---

## 5. Phases

Each phase lands green: unit tests pass, `python -m compileall -q .` clean,
and (from Phase 2 on) the end-to-end smoke command of the phase. All work
happens on this branch; the Rust code stays untouched on `main`.

### Phase 0 — Branch + scaffold + plan (this commit)
- `python` branch created; Rust-specific files removed (`src/`,
  `Cargo.*`, `.github/`); Python test helpers kept
  (`tests/nat-sim/*.py`, `tests/telegram/mock_bot_api.py` — already Python,
  reused as-is).
- Scaffold: `pyproject.toml` (single dep `aioquic>=1.7,<2`, console script
  `p2p-tunnel`), package skeleton, stub `main()` (`--help`/`-V` work).
- `PLAN.md` (this file) + `PROGRESS.md` dev log.
- **Done-when:** `pip install -e .` in a venv, `p2p-tunnel --help` prints,
  `python -m compileall -q .` clean. ✅

### Phase 1 — Config + CLI parsing
- `config.py`: dataclass `Config` + `TelegramConfig`, `tomllib` load,
  defaults, `stun_servers` non-empty validation.
- `cli.py`: argparse `Cli.parse(argv)`, `parse_peer_addr(s) -> ip:port`
  (IPv4 only in MVP), `prompt_peer_addr(read_line)` loop with
  `PromptBail` (ModeToggled / Aborted / Eof).
- Tests (port of Rust `config.rs` + `cli.rs` tests, 6):
  `loads_full_config`, `loads_telegram_section`, `telegram_timeout_override`,
  `explicit_overrides_win`, `loads_missing_stun_servers_errors`,
  `parse_peer_addr_valid/invalid`.
- **Done-when:** all green; `p2p-tunnel --config <sample>` loads
  `config.toml`.

### Phase 2 — STUN
- `stun.py`: encode/parse per §4, `UdpSocket` helper (bind, `send_to`,
  `recv_from` via `loop.sock_*`, local_port, close, `into_raw()` for
  handover), `discover_public_addr(sock, servers)`.
- Tests (port of Rust `stun.rs` tests, 7): `encodes_binding_request`,
  `parses_xor_mapped_response_v4`, `parses_plain_mapped_response_v4`,
  `skips_unknown_attrs`, `rejects_wrong_transaction_id`,
  `rejects_non_stun_packet`, `rejects_error_response` + a live test against
  a local `tests/nat-sim/stun_server.py` instance.
- **Done-when:** tests green + real `stun.l.google.com:19302` round-trip
  from this machine prints the public address.

### Phase 3 — Manual address exchange
- Wire `resolve_addrs_manual` into a first end-to-end `main()` (plain
  logging, no TUI yet): STUN → print own address → prompt → return
  `(own, peer)`.
- Tests: prompt loop behavior (valid line, invalid re-prompt, EOF).
- **Done-when:** two terminals on this machine can exchange addresses
  manually (peer = loopback trick: point one side's peer address at
  127.0.0.1:<other local port>).

### Phase 4 — Hole punching
- `punch.py` per §4.
- Tests (port of Rust `punch.rs`, 3): `punch_succeeds_when_peer_sends`,
  `punch_ignores_other_senders`, `punch_times_out_without_peer` (short
  timeouts).
- **Done-when:** loopback punch succeeds; timeout error text verified.

### Phase 5 — Role
- `role.py` per §4.
- Tests (port of Rust `role.rs`, 5): `determine_role`, `v4_lower_is_server`,
  `roles_always_opposite`, `v4_always_beats_v6`, `v6_orders_numerically`,
  `same_ip_falls_back_to_port`.
- **Done-when:** green.

### Phase 6 — Certificate + QUIC configuration
- `quic.py` part 1: `generate_self_signed_cert()` via `cryptography`
  x509 (P-256, CN+SAN, 30 days), `fingerprint(cert) -> str`;
  `build_client_config(keep_alive)` / `build_server_config(cert, key,
  keep_alive)` returning `QuicConfiguration` objects.
- Tests (port of Rust `quic.rs` tests, 4): cert/key generated,
  fingerprint stable+distinct+64-hex, both configs build (with/without
  keep-alive).
- **Done-when:** green; cert parseable by `openssl x509 -text` in a shell.

### Phase 7 — QUIC endpoint on the reused socket
- `quic.py` part 2: `attach_client(sock, cfg) -> protocol` (handshake
  included, `wait_connected`), `attach_server(sock, cfg, stream_handler)
  -> (server, first_connection_future)`; keep-alive task
  `start_keep_alive(protocol, interval)`.
- Tests: loopback attach of both sides (fresh sockets, no punch) —
  handshake completes over 127.0.0.1. *(Deliberate deviation from the Rust
  decision to skip loopback QUIC tests: the reason there was quinn
  socket-ownership ambiguity; with aioquic + `sock=` handover it's
  deterministic and cheap.)*
- **Done-when:** loopback handshake green, including the
  `create_datagram_endpoint(sock=punched_sock)` path with a pre-used
  socket (send/receive a STUN datagram through it first, then hand over).

### Phase 8 — Client-side bridge
- `tunnel.py`: `bridge_halves`, `run_client_side(conn, port)` (listener on
  127.0.0.1:port, per-connection stream).
- Tests (port of Rust `tunnel.rs`, 3): `bridge_halves_moves_bytes_both_ways`,
  `bridge_halves_propagates_half_close`, `bridge_halves_closes_on_error` +
  loopback end-to-end: client-side listener ↔ server-side echo over a real
  QUIC connection on 127.0.0.1.
- **Done-when:** green.

### Phase 9 — Server-side bridge
- `run_server_side(server, target)`: per incoming stream → TCP connect →
  bridge; unreachable target → warn + FIN.
- Tests: with `tests/nat-sim/echo_target.py`; unreachable-target behavior.
- **Done-when:** green; `nc` through a loopback tunnel reaches the echo
  target.

### Phase 10 — Pipeline wiring + errors
- `main.py`: full pipeline per §3 (roles, required-config validation with
  Rust-identical messages, `hint_for()`, exit codes, TTY auto-TUI hook
  placeholder), `__main__.py`.
- **Done-when:** `p2p-tunnel --no-tui --config config.toml` runs the whole
  manual flow on two loopback instances; missing-key error + hint verified;
  `error:`/`hint`/exit-1 contract matches Rust for all four hint classes.

### Phase 11 — Logging polish
- Stdlib logging setup per §3 (env var precedence, `--verbose`, TUI-off
  level), per-stage `info` lines with the same message content as Rust
  (they are the UX).
- **Done-when:** side-by-side log comparison with the Rust binary (manual
  loopback run) shows equivalent stages/wording.

### Phase 12 — Telegram signaling
- `telegram.py` per §4: `Telegram.init` (getMe), `handshake(cfg, aborted)`,
  `send_own_addr`, `wait_peer_addr(cfg, aborted)`; `urllib` POST via
  executor; payload build/classify per the PTUN spec; `PTUN_TELEGRAM_API_BASE`
  override.
- Tests: port the Rust `telegram.rs` classify suite (17 tests) against
  `tests/telegram/mock_bot_api.py` (unchanged), plus `handshake`/`send`/
  `wait` flows with the mock.
- **Done-when:** green; a real two-bot run documented in PROGRESS (or
  mocked e2e if no real bots are available in this environment).

### Phase 13 — TUI
- `tui_state.py` (direct port + its 4 Rust tests:
  `phase_transitions_advance_stuck_actives`, `active_phase_reports_frontier`,
  `exchange_mode_round_trips`, `logs_are_bounded`).
- `tui.py`: curses render thread, event queue, stepper/connection/log
  panels, inline prompt editor, `t` toggle, `q`/Esc/Ctrl-C abort, error
  banner + 3 s dwell before exit (Rust behavior), 400 ms final-paint dwell.
- `apply_event`-style unit tests (the Rust `tui.rs` has one such test) —
  event→state folding is testable headless; the curses drawing itself is
  exercised in a real-terminal smoke run.
- **Done-when:** state tests green; manual smoke: full run under the TUI
  on a real terminal, prompt typing visible, `t` toggle works, `q` aborts
  cleanly, error path paints red.

### Phase 14 — Loopback e2e test (new, Python-specific)
- `tests/test_e2e_loopback.py`: in one process, spawn a full server-side
  pipeline + client-side pipeline over 127.0.0.1 (two UDP sockets, STUN
  against the local `stun_server.py`, manual peer address exchange
  pre-seeded, real QUIC handshake, real TCP bridge to the echo target).
  Assert bytes round-trip and clean shutdown.
- **Done-when:** green under `unittest discover`.

### Phase 15 — Real NAT verification
- Port/author `tests/nat-sim/` driver: run `stun_server.py` + a NAT
  simulator (two "inside" addresses behind simulated mappings) and drive
  two `p2p-tunnel` processes through STUN → exchange → punch → QUIC →
  echo-target round-trip over the simulated NAT; plus `TESTING.md` with
  the two-real-machines procedure (the Rust project's Phase 12 artifact).
- **Done-when:** driver green in CI locally; two-machine run recorded in
  PROGRESS.md.

### Phase 16 — Docs, CI, cleanup
- Rewrite `README.md` as the Python user manual (install:
  `python3 -m venv .venv && pip install .`; usage; config reference;
  Telegram setup; TUI; troubleshooting; how it works; limitations;
  security note on the MVP trust model).
- `.github/workflows/ci.yml` (Python): matrix 3.11–3.14 (linux + windows +
  macos), `pip install -e .`, `python -m unittest discover -v`,
  `python -m compileall -q .`. Windows: TUI tests skip (no `curses`).
- `py.typed`, final `PROGRESS.md` entry, tag `v0.1.0-py`.
- **Done-when:** CI green; README matches actual behavior.

---

## 6. Test strategy

- **`unittest` only** (stdlib; `IsolatedAsyncioTestCase` for async tests).
  No pytest, no test-only dependencies.
- Test tree mirrors the Rust one:
  ```
  tests/
  ├── test_cli.py test_config.py test_stun.py test_punch.py test_role.py
  ├── test_quic.py test_tunnel.py test_telegram.py
  ├── test_tui_state.py test_tui_events.py
  ├── test_e2e_loopback.py
  ├── nat-sim/        (reused from Rust project: stun_server.py,
  │                    echo_target.py, probe_client.py, + new nat_sim driver)
  └── telegram/mock_bot_api.py   (reused unchanged)
  ```
- Rust test parity: all 46 Rust tests have a Python counterpart (mapped in
  §5 per phase); the Python version **adds** loopback QUIC/e2e tests (see
  Phase 7/14 justification).
- Network-touching tests (real STUN) are marked and skipped when offline
  (`unittest.skipIf` on a reachability probe) so CI stays hermetic.
- Concurrency tests keep the Rust timeouts scaled down (e.g. 30 s punch
  timeout → 2 s in tests) — behavior identical, wall time short.

## 7. Risks & mitigations

| Risk | Mitigation |
|---|---|
| aioquic API drift (we use `QuicServer` internals + `sock=` handover) | Pin `aioquic>=1.7,<2`; isolate all aioquic contact in `quic.py`; fallback = rebind fresh socket to the same local port (§2) |
| asyncio socket handover (sock_recvfrom → create_datagram_endpoint on the same fd) | Phase 7 test uses a *pre-used* socket (STUN datagram through it first); Phase 14 covers it end-to-end |
| `curses` absent on Windows | TUI auto-disabled; `--tui` warns; CI skips TUI tests on Windows |
| Pure-Python QUIC throughput < Rust quinn | Acceptable for the MVP use cases (SSH, file transfer, remote shells); documented as a known limitation; `cryptography` does the TLS crypto in C |
| Python 3.14 quirks in asyncio | CI matrix includes 3.14; local dev on 3.14.8 |
| Telegram bot-to-bot not testable in CI | Mock API (reused) covers protocol; real run is a documented manual step (Phase 12/15) |
| Fork divergence from the Rust oracle | Rust `main` is frozen; any behavior change goes to this plan first, then to both codebases |

## 8. Verification (run at every phase gate)

```sh
python3 -m venv .venv && . .venv/bin/activate
pip install -e .
python -m compileall -q p2p_tunnel tests
python -m unittest discover -s tests -v
p2p-tunnel --help && p2p-tunnel -V
```
