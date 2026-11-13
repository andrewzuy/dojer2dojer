# PROGRESS — Python port development log

This is the development log for the Python rewrite (branch `python`).
The Rust implementation on `main` is frozen and serves as the reference
(oracle) — see `PLAN.md` for the full plan. Each entry is appended in
chronological order; latest last.

---

## 2026-07-21 — Phase 0: branch, scaffold, plan

**What happened**

- Created branch `python` from `main` (tip `f2dc2a4`, Rust `v0.1.0`).
- Removed the Rust-only files from this branch: `src/`, `Cargo.toml`,
  `Cargo.lock`, `.github/` (Rust CI). Kept: `config.toml` (format
  unchanged — the Python port reads the same file), `LICENSE`, and the
  already-Python test helpers `tests/nat-sim/*.py` and
  `tests/telegram/mock_bot_api.py` (reused as-is).
- Wrote `PLAN.md`: full port plan — goals, the verified `aioquic` API
  spike, architecture, wire/behavior parity contract, 17 phases
  (0–16) with per-phase tests mapped 1:1 to the 46 Rust tests, test
  strategy, risks.
- Scaffold:
  - `pyproject.toml` — setuptools, `requires-python >=3.11`, **one**
    direct dependency (`aioquic>=1.7,<2`), console script `p2p-tunnel`.
  - `p2p_tunnel/` package: `__init__.py` (version 0.1.0), `__main__.py`,
    stub `main.py` (`--help`/`-V` only; pipeline lands in Phases 1–13).
  - `README.md` replaced with a short stub pointing at `PLAN.md`
    (full manual rewritten in Phase 16).
  - `.gitignore`: added `.venv/`, `__pycache__/`, `*.pyc`, `build/`,
    `dist/`, `*.egg-info/`.
- `PROGRESS.md` (this file) replaced the Rust scratchpad — the Rust
  development history remains available on `main`.

**Dependency decision (the big one)**

- Exactly one direct third-party dependency: **aioquic 1.7.2**
  (pure-Python QUIC + TLS 1.3, BSD-3). Verified it installs cleanly on
  Python 3.14 and, crucially, that its asyncio layer can be driven on
  **our** pre-bound UDP socket — on both the client side
  (`loop.create_datagram_endpoint(..., sock=our_sock)` +
  `QuicConnectionProtocol`) and the server side (`QuicServer` is a plain
  `asyncio.DatagramProtocol`; instantiate directly and attach our
  socket). This preserves the Rust design where the single UDP socket
  carries STUN → hole punching → QUIC.
- Consequence: STUN, hole punching, role, config, CLI, Telegram, TUI,
  and tests are all standard library. The TUI uses `curses` (no
  `ratatui` equivalent in stdlib — `curses` is stdlib on Linux/macOS;
  auto-disabled on Windows).
- Deviation noted in the plan: the Python port **adds** loopback QUIC
  e2e tests (the Rust project skipped them due to quinn socket-ownership
  ambiguity; aioquic makes them deterministic and cheap).

**Verified (spike results, all reproducible)**

- `aioquic 1.7.2` + `cryptography 50.0.2` in a fresh venv on Python 3.14.8.
- `QuicConfiguration` fields: `verify_mode` (client accept-any =
  `ssl.CERT_NONE`; 1.7.2 has no `is_trusted`), `idle_timeout` (default
  60 s), `server_name`, `certificate`/`private_key` accept
  `cryptography` objects directly.
- `QuicConnectionProtocol.create_stream(False)` returns real
  `asyncio.StreamReader`/`StreamWriter`; `write_eof()` sends the QUIC
  FIN → half-close native → the TCP↔QUIC bridge is the same copy-both-ways
  shape as Rust.
- `QuicServer(configuration=..., stream_handler=...)` receives incoming
  streams via the callback — the server-side bridge hook.
- `protocol.ping()` awaits a PING ack — used by the keep-alive task
  (every `keep_alive_interval_secs`, both roles, cancellable).
- Peer cert reachable post-handshake at
  `protocol.connection.tls._peer_certificate` (private attr; used
  defensively for the extra fingerprint log line).

**Next (Phase 1)**

- `config.py` (tomllib load + defaults + validation) and `cli.py`
  (argparse, `parse_peer_addr`, prompt loop) with their 6 ported tests.

---

## 2026-07-21 — Phase 1: config + CLI parsing

**What happened**

- `p2p_tunnel/config.py` — direct port of Rust `src/config.rs`:
  dataclasses `Config` + `TelegramConfig`, `tomllib` load, same defaults
  (500 ms / 30 s / 5 s / 120 s), same validation (missing/empty
  `stun_servers` → `config:` error; malformed TOML → `parsing config file`
  error; read failure → `reading config file` error; wrong types rejected;
  unknown keys ignored). Error strings keep the Rust wording because
  `hint_for()` matches on substrings.
- `p2p_tunnel/cli.py` — direct port of Rust `src/cli.rs`:
  - `Cli.parse(argv)` via argparse: `--config` (default `./config.toml`),
    `--verbose`, `--telegram`, `--tui`, `--no-tui`, `-V/--version`.
  - `parse_peer_addr(s) -> (host, port)` mirroring Rust's
    `SocketAddr::from_str`: IPv4 + IPv6 `[v6]:port` literals, port required
    and in 1..65535.
  - `prompt_peer_addr(read)` — the re-prompting loop, decoupled from the
    input transport via an injected `read()` callable returning a
    `PromptOutcome` (line / mode-toggled / aborted / eof); OSError from
    `read` maps to `Aborted` (Rust parity). Bail reasons are exception
    classes (`ModeToggled` / `Aborted` / `Eof`, all `PromptBail`) instead
    of an `Err` enum — Pythonic, same contract.
  - `read_line_stdin(prompt)` — the plain-stdin transport used when the
    TUI is off; the TUI will supply its own transport in Phase 13.
- `main.py` now parses the real `Cli` (pipeline body still a stub).

**Tests** — `tests/test_config.py` (12) + `tests/test_cli.py` (14) = 26 total,
all green. Ports the 6 Rust tests (`loads_full_config`,
`loads_telegram_section`, `telegram_timeout_override`,
`explicit_overrides_win`, `parses_valid_addrs`, `rejects_invalid_addrs`) and
adds: `PTUN READY` secret loading, missing/empty `stun_servers` errors,
malformed TOML, nonexistent file, bad port type, unknown-keys-ignored,
CLI flag parsing, and the full prompt-loop contract (empty/invalid
re-prompt with exact stderr messages, toggle/abort/EOF bails, OSError→abort).

**Notes**

- `unittest discover` needs `-s tests` (tests are not a package on purpose —
  no `tests/__init__.py`, same as the Rust test-helper layout); PLAN.md
  §8 verification updated accordingly.
- One test-design bug caught and fixed on the first run: my
  `test_mode_toggled_bails` fed a *valid* line before the toggle — the loop
  correctly returns on the first valid line, so the toggle was unreachable;
  the test now asserts the reachable toggle positions only.

**Next (Phase 2)**

- `stun.py`: RFC 5389 encode/parse (byte-identical layout), the `UdpSocket`
  asyncio helper (the one socket), `discover_public_addr` — 7 ported tests +
  a live round-trip against the local `tests/nat-sim/stun_server.py`.

---

## 2026-07-21 — Plan v2: orchestration changes (user decision)

The orchestration diverges from the Rust oracle by explicit product
decision. `PLAN.md` rewritten as v2; the divergence table (§2) is the
single source of truth. Summary of the changes:

- **D1 — role is user-selected, not derived.** At startup the app asks for
  the role (client/server). Telegram negotiation cross-checks the two
  declarations; if both sides picked the same role the TUI shows a
  misconfiguration message and returns to role selection. The Rust
  IP-derived role is kept only as the **legacy fallback** (peer bot is a
  Rust version that sends no role) and for the ported oracle tests.
  Server setting = the service to expose (`remote_target_addr`, ip+port);
  client setting = the local TCP port only (`local_tcp_listen_port`,
  localhost-only entry point). Config validation becomes role-aware.
- **D2 — Telegram is the default channel** when a `[telegram]` table
  exists; manual is the fallback (automatic on Telegram failure, or forced
  via new `--manual`/`--no-telegram` flags). `resolve_exchange_mode()` is
  a pure tested function.
- **D3 — reconnect supervisor.** Any tunnel/QUIC loss (but NOT a
  stream-level failure — one localhost client leaving, or the exposed
  service being down, only affects that stream) triggers a **full
  re-negotiation** via the long-lived Telegram channel (READY + v1 lines
  again — idempotent, offset-based polling guarantees per-attempt
  freshness), with exponential backoff 2 s → 30 s cap (reset after 30 s
  stability), unlimited attempts, TUI shows "re-negotiating (attempt N)".
  Fresh UDP socket per attempt. The getUpdates polling loop lives for the
  whole app lifetime.
- **D4 — PTUN protocol v1.1.** `PTUN READY <secret>` stays byte-identical
  (verified: the Rust classifier does an exact `body.trim() != secret`
  match, so the role cannot ride on that line). New **optional** line
  `PTUN ROLE <client|server>` right after READY. Rust peers ignore it
  (their classifier only matches the `READY `/`v1 ` prefixes); a Python
  peer with no ROLE line from the peer falls back to the IP-derived role
  with a TUI warning. No version bump; Py↔Rust interop preserved.
- **D5 — TUI setup screen.** Role + role-specific setting + channel, in
  one screen, prefilled from config, editable. Plain-log mode uses stdin
  prompts with the same contract.
- **Flow (the spec, PLAN.md §2):** S1 setup (role) → T1 Telegram
  handshake + role cross-check (BEFORE STUN, as in Rust f2dc2a4) → T2
  STUN → T3 address exchange over the established Telegram connection →
  T4 hole punching → T5 QUIC tunnel → T6 bridge; on loss → back to T1
  with backoff.

**Technical checks done for this revision**

- Rust `classify_ready` re-verified: exact secret match ⇒ the READY line
  format cannot change ⇒ separate `PTUN ROLE` line (D4).
- **Windows TUI verified:** stock CPython on Windows ships no `curses`
  (`_curses` not built). `windows-curses 2.4.2` (PSF-2, wheels for
  cp311–cp314 incl. `win_amd64`) installs the genuine
  `_curses`/`_curses_panel` extension modules, so stdlib
  `import curses` works as-is. Plan: optional extra
  `p2p-tunnel[tui] = ["windows-curses; sys_platform == 'win32'"]`,
  runtime `import curses` with graceful fallback to plain logs + hint,
  and a constraint to only classic ncurses calls (the core
  windows-curses implements). Windows job added to the CI matrix (Phase 16).

**Phase renumbering (consequence):** Telegram moved up to Phase 8 (it is
  now the default path), new Phase 9 (role model + setup + CLI v2),
  Phase 10 (pipeline wiring v1), Phase 11 (reconnect supervisor), Phase 12
  (TUI incl. Windows), 13 logging, 14 loopback e2e (incl. drop→
  re-negotiate), 15 real NAT + reconnect drill, 16 docs/CI. Phases 2–7
  (STUN → bridges) are unchanged content-wise.

**Next (Phase 2)** — unchanged from the Phase 1 entry: `stun.py`.

---

## 2026-07-21 — Phase 2: STUN

**What happened**

- `p2p_tunnel/stun.py` — direct port of Rust `src/stun.rs`:
  - Same constants (`DEFAULT_STUN_PORT = 19302`, magic `0x2112A442`,
    msg types, attr types, 3 s per attempt, 2 rounds, 512-byte buffer).
  - `encode_binding_request(txn) -> bytes` (20-byte header, no attrs).
  - `parse_binding_response(data, txn, server) -> (host, port)` —
    validates type/magic/txn in Rust order, walks attrs with 4-byte
    padding, XOR-MAPPED-ADDRESS first with MAPPED-ADDRESS fallback,
    v4 and v6 (v6 key = magic||txn).
  - Error classes `StunRejected` / `StunMalformed` / `StunIo` keep the
    Rust message wording (`"STUN server … rejected request: …"`,
    `"malformed STUN response from …: …"`, `"I/O error talking to STUN
    server …: …"`); discovery-level failure stays
    `"STUN discovery failed: {last} (tried servers: …)"` for
    `hint_for()` matching.
  - `UdpSocket` — the one socket: STUN → punch → QUIC all share it.
    `create()` binds `0.0.0.0:0` non-blocking; I/O via
    `loop.sock_sendto` / `loop.sock_recvfrom`; `into_raw()` detaches the
    underlying `socket.socket` for the QUIC handover
    (`loop.create_datagram_endpoint(sock=…)`); context-manager support.
  - `discover_public_addr(sock, servers)` — per-server, per-round loop;
    `loop.getaddrinfo` for resolution (numeric literals work); ignores
    datagrams from anyone other than the STUN server (the socket will
    later carry punch traffic too).
  - Logging mirrors the Rust tracing lines (debug: send/response;
    warn: timeout/failure/unresolvable).
- Project venv `.venv` (Python 3.14.8, `aioquic 1.7.2`) now used for all
  gates.

**Tests** — `tests/test_stun.py`: all 7 Rust tests ported
(`encodes_binding_request`, both v4 mapped-attr parses, unknown-attr
skip, wrong-txn rejection, non-STUN rejection, error-response rejection)
plus: bad-magic rejection, no-mapped-attr rejection, v6
XOR-MAPPED-ADDRESS round-trip (RFC key = magic||txn), txn-length guard,
`resolve_server` (default port, explicit port, bad port, out-of-range,
empty host, unresolvable), async loopback discovery against an in-test
responder mirroring `nat-sim/stun_server.py`'s reply logic, stray-traffic
ignored, unreachable-server error message contract, `UdpSocket`
round-trip + `into_raw` detach, and a live test
(`PTUN_LIVE_STUN=1`) against the real `stun.l.google.com:19302`.
Suite: 50 tests, all green.

**Gate verified**

- `python -m compileall -q p2p_tunnel tests` — clean.
- `python -m unittest discover -s tests` — 50 OK (1 skipped: live test).
- Live: `PTUN_LIVE_STUN=1 … test_stun.py` →
  `LIVE STUN: public address is 178.125.204.132:59942`.

**Notes**

- `tests/nat-sim/stun_server.py` only answers the netns-sim client IPs
  (10.0.0.1 / 10.1.0.1) and programs iptables, so a loopback unit test
  needs its own responder; the real server stays the Phase 15 fixture.
- Three first-run test bugs caught: `IsolatedAsyncioTestCase` has no
  `.loop` in 3.12+ (use `get_running_loop()`), my v6 test XORed against
  the cookie instead of the 16-byte key (library was right), and the
  echo test forgot the actual echo. `UdpSocket.__aenter__` had to be
  `async def` (caught by the live test's `async with`).

**Next (Phase 3)** — `punch.py`: simultaneous hole punching on the shared
socket (500 ms interval, 30 s default timeout, first-packet rule), with
the 3 Rust tests scaled down (30 s → 2 s).

---

## 2026-07-21 — Phase 3: hole punching

**What happened**

- `p2p_tunnel/punch.py` — direct port of Rust `src/punch.rs`:
  - 8-byte random nonce sent to the peer every `max(interval_ms, 10)` ms;
    first punch goes out at once (Rust's immediate first tick).
  - Same socket as STUN (NAT binding continuity) and later QUIC.
  - Datagrams from non-peer addresses ignored (debug-logged); recv `OSError`
    treated as ICMP-unreachable noise and punching continues (the Windows
    case, kept for parity).
  - Success logged with from/bytes/sent/elapsed_ms, exactly as Rust.
  - `PunchTimeout` message is Rust-byte-identical:
    `"hole punching timed out after {N}s: no packet from {ip:port} (sent
    {n} punch packets)"`; send failure → `PunchError("sending punch
    packet: …")`.
  - asyncio translation of Rust's 3-arm `select!`: per loop iteration, a
    sleep-to-next-tick task and a recv task are raced with
    `asyncio.wait(FIRST_COMPLETED)`; the loser is cancelled (a cancelled
    recv loses nothing — datagrams wait in the kernel buffer).
- Signature takes `interval_ms` / `timeout_secs` directly (not a full
  `Config`) so tests can scale them; the pipeline passes config values.

**Tests** — `tests/test_punch.py`: the 3 Rust tests ported
(`punch_succeeds_when_peer_sends` with a 120 ms-delay fake peer,
`punch_ignores_other_senders` with a 50 ms stranger + 150 ms real peer,
`punch_times_out_without_peer` against 127.0.0.1:9 at 1 s as in Rust) plus
two new: timeout message reports the actual sent count, and an eager peer
answering before the first recv starts (kernel-buffer continuity).
Suite: 55 tests, all green (2.2 s).

**Next (Phase 4)** — `quic.py`: `cryptography`-generated self-signed
cert (CN=`p2p-tunnel`), SHA-256 fingerprint, `QuicConfiguration` builders
for both roles (client: `verify_mode=CERT_NONE`, `server_name="p2p-tunnel"`;
keep-alive PING task since aioquic has no built-in interval).

---

## 2026-07-21 — Phase 4: certificates + QUIC configuration

**What happened**

- `p2p_tunnel/quic.py` — port of the Phase-4 surface of Rust `src/quic.rs`:
  - `CERT_CN = "p2p-tunnel"` (cert CN + DNS SAN, and the TLS SNI the
    client sends — Rust: `endpoint.connect(peer_addr, CERT_CN)`).
  - `generate_self_signed_cert() -> (cert_der, key, fingerprint)`:
    fresh ECDSA P-256 self-signed cert via `cryptography` (rcgen's
    equivalent), 30-day validity with 5 min start slack, fingerprint
    logged for out-of-band comparison — same MVP security model as Rust
    (client accepts any cert; humans compare fingerprints).
  - `fingerprint(cert_der)` — SHA-256 hex, 64 lowercase chars.
  - `build_client_config()` — `QuicConfiguration(is_client=True,
    server_name=CERT_CN, verify_mode=ssl.CERT_NONE, idle_timeout=30.0)`.
    CERT_NONE is the Python equivalent of Rust's
    `AcceptAnyServerCert` (TLS 1.3 handshake signatures are still really
    verified by `cryptography`). idle_timeout 30 s = quinn's default.
  - `build_server_config(cert_der, key)` — presents our self-signed cert.
  - `start_keep_alive(protocol, interval_secs)` — the Python equivalent of
    Rust's `transport_config_with_keep_alive`: aioquic has no built-in
    keep-alive interval, so a task calls `await protocol.ping()` every N
    seconds and cancels itself when the connection dies; `None`/`<= 0`
    disables.
  - **ALPN:** verified the Rust side sets none (quinn default) ⇒ Python
    sends none too, so Python↔Rust and Python↔Python handshakes agree.
  - Endpoint attachment (create_endpoint/connect/accept) is Phase 5.

**Tests** — `tests/test_quic.py`: the 4 Rust tests ported
(`generates_cert_and_key`, `fingerprint_is_stable_and_distinct`,
`client_and_server_configs_build`, keep-alive value acceptance) plus:
P-256 key shape + CN/SAN content check, fresh key per call, no-ALPN
parity, and a keep-alive task that stops pinging once the connection
dies. Suite: 62 tests, all green.

**Next (Phase 5)** — QUIC endpoint over the reused socket:
`create_endpoint` via `loop.create_datagram_endpoint(sock=…)` with
`QuicConnectionProtocol` (client) / `QuicServer` (server), `connect()`
with `wait_connected()`, `accept()`, and a loopback handshake smoke test.

---

## 2026-07-21 — Phase 5: QUIC endpoint over the reused socket

**What happened**

- `p2p_tunnel/quic.py` part 2 — endpoint attachment (Rust `create_endpoint`/`connect` parity):
  - `attach_client(sock, config, stream_handler=None)` — builds a
    `QuicConnection` + `QuicConnectionProtocol` and hands **our punched
    socket** to the event loop via `loop.create_datagram_endpoint(sock=…)`.
    Same fd ⇒ the punched 4-tuple and its NAT mapping survive the
    handover (this is the whole point of the shared socket).
  - `attach_server(sock, config, stream_handler=None, on_connection=None)` —
    instantiates aioquic's `QuicServer` (a plain `asyncio.DatagramProtocol`)
    directly on our socket. aioquic has no quinn-style `accept()`: it
    creates one `QuicConnectionProtocol` per peer connection, so
    `on_connection` (a callback) is the notification hook — the pipeline
    will use it to await the first connection.
  - `connect(protocol, peer_addr, timeout=30)` — `protocol.connect(addr,
    transmit=True)` + `wait_connected()`; timeout → `QuicError("QUIC
    handshake with ip:port timed out after Ns")`; peer-terminated →
    `QuicError("…failed: …")`.
  - `close_endpoint(endpoint)` — closes connection(s) + datagram transport.
    Verified asyncio's selector datagram transport **owns** the socket it
    is handed and closes it ⇒ closing the endpoint fully releases the
    shared socket for the supervisor's next fresh-socket attempt (v2
    reconnect design).
  - `peer_certificate_fingerprint(protocol)` — SHA-256 of the peer's leaf
    cert for out-of-band comparison (client side). Reads aioquic's
    private `_quic.tls._peer_certificate`; returns `None` if the API
    moves (nice-to-have trust aid, not load-bearing).

**Phase 4 bug found by Phase 5**

- `build_server_config` put the DER bytes in `certificate_chain`, but
  aioquic 1.7.2 requires the **leaf** in `configuration.certificate` as
  an `x509.Certificate` object (chain = the rest). A server connection
  with the old config raised `ValueError: SSL certificate is required
  for a server`. Fixed + the config test now asserts the new shape.

**Tests** — `tests/test_quic.py` gains `LoopbackHandshakeTests`:
- `test_loopback_handshake_and_stream_roundtrip` — the Phase 5 done-when.
  Two `UdpSocket`s, each **pre-used** with a real STUN Binding Request
  round-trip (the `create_datagram_endpoint(sock=pre_used_sock)` path the
  plan calls out), then `attach_server`/`attach_client`, real QUIC v1 +
  TLS 1.3 handshake, server sees the connection as the first Initial
  lands, client `create_stream` → server `stream_handler`, b"ping"/b"pong"
  round-trip with half-close, peer cert fingerprint == our server
  fingerprint (accept-any MVP model), keep-alive ping task alive on the
  real connection, clean `close_endpoint` teardown.
- `test_connect_times_out_against_closed_port` — handshake timeout →
  `QuicError` with the "timed out" message.
- **Documented deviation from Rust:** the Rust project skipped loopback
  QUIC tests (quinn socket-ownership ambiguity); with aioquic + `sock=`
  handover they are deterministic, so we run them (PLAN.md Phase 5).

**Gate**

- `python -m compileall -q p2p_tunnel tests` — clean
- `python -m unittest discover -s tests -v` — **64 tests, all green**
  (1 live STUN test skipped without `PTUN_LIVE_STUN=1`)

**Next (Phase 6)** — client-side bridge: `tunnel.py` with `bridge_halves`
(the 3 ported Rust tests) and `run_client_side` (127.0.0.1 TCP listener,
per-connection QUIC stream), loopback e2e client side ↔ echo over real
QUIC.

## 2026-11-12 — Phase 6: client-side bridge (implementation only)

Per user decision the phase is split: **Phase 6 = implementation**
(`bridge_halves` + `run_client_side`), the tests move to **Phase 6b**
(separate commit). PLAN.md updated accordingly.

**`p2p_tunnel/tunnel.py`**

- `bridge_halves(read_a, write_a, read_b, write_b) -> (bytes_a, bytes_b)`
  — Rust parity for `tunnel::bridge_halves`. Two independent copy tasks
  (direction A: `read_a → write_a`, B: `read_b → write_b`), 64 KiB
  chunks, `write_eof()` after EOF in each direction (half-close
  propagation — one side's EOF does not kill the other direction),
  `asyncio.gather(..., return_exceptions=True)`, first error (A before B)
  surfaces as `TunnelError("copy <name>: <err>")` mirroring the Rust
  `tokio::join!` + `context` ordering.
- `run_client_side(protocol, listen_port)` — Rust parity for
  `tunnel::run_client_side`. Binds `127.0.0.1:<port>` (loopback only),
  one task per accepted TCP connection, each opens a **fresh
  bidirectional QUIC stream** (concurrent connections are independent),
  runs until `protocol.wait_closed()`, then stops the local listener.
  Bind failure → `TunnelError` with the "is the port already in use?"
  hint.
- `_bridge_client_stream` — per-connection glue; errors are logged,
  never raised (one bad local connection must not take down the tunnel).

**Verification** — the full committed suite (64 tests) stayed green, and
the implementation was verified end-to-end over **real QUIC loopback**
(two `UdpSocket`s, `attach_server` echo handler, `attach_client` +
`run_client_side`): handshake OK, local TCP listener OK, 12-byte echo
round-trip OK, half-close/EOF propagation OK, `run_client_side` returns
when the QUIC connection closes. (The throwaway check script was not
committed — the permanent e2e test lands in Phase 6b.)

**Known bugs in the deferred draft** (`tests/test_tunnel.py`, stays
untracked until 6b):

- `_MemPipe`/`_MemEnd` wiring is self-looping (each end's writer feeds
  its own reader), so the in-memory bridge tests deadlock. Needs:
  `end1.reader=_r1`/`end1.writer→_r2`, `end2.reader=_r2`/
  `end2.writer→_r1`.
- The e2e `on_stream` is `async def`, but aioquic calls the stream
  handler **synchronously** (`quic_event_received` →
  `self._stream_handler(reader, writer)`) — must be a sync function that
  spawns the echo task (as `tests/test_quic.py` does).
- The error-context test never feeds data into direction A, so the
  failing writer is never reached; feed `half_a.reader` before the EOF.

**Gate**

- `python -m compileall -q p2p_tunnel tests` — clean
- `python -m unittest tests.test_config tests.test_cli tests.test_stun
  tests.test_punch tests.test_quic -v` — **64 tests, all green** (test
  discovery over `tests/` includes the untracked draft, which is
  intentional until 6b fixes it)
- real-QUIC loopback implementation check — 5/5 passed

**Next (Phase 6b)** — fix the three drafted-test bugs above, get
`tests/test_tunnel.py` green, commit it separately.
