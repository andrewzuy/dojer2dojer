# PLAN — Python rewrite of p2p-tunnel

Status: **active**. This branch (`python`) rewrites the Rust `p2p-tunnel`
(on `main`, frozen reference at `f2dc2a4`) in Python. `PROGRESS.md` is the
development log.

> **Plan v2 (2026-07-21)** — the orchestration diverges from the Rust
> oracle by explicit product decision (see §2 "Divergences"): the role is
> **user-selected at startup** and cross-checked over Telegram, **Telegram
> is the default** channel (manual = fallback), and the app is a
> **reconnect supervisor** (full re-negotiation whenever the tunnel drops).
> The *internal* behavior of each step (STUN wire format, punch semantics,
> QUIC setup, bridge semantics, Telegram API handling) still follows the
> Rust code; where this document and the Rust code disagree about
> *orchestration*, this document wins.

---

## 1. Goals

1. **Feature parity-plus** with the Rust tool (STUN → address exchange →
   simultaneous hole punching → QUIC/TLS 1.3 byte pipe over the punched
   socket → TCP↔QUIC bridge, live TUI, keep-alive PINGs, actionable error
   hints) **plus** the v2 orchestration (§2): startup role selection,
   Telegram-first signaling, role conflict detection, automatic
   re-negotiation on tunnel loss.
2. **As few third-party dependencies as possible.** Decision (verified,
   §3): exactly **one** direct runtime dependency — `aioquic` (pure-Python
   QUIC + TLS 1.3, BSD-3; pulls `cryptography`, `h11`, `pyrfc3339`
   transitively). Everything else is stdlib: `asyncio`, `tomllib`,
   `argparse`, `urllib`, `ssl`, `hashlib`, `curses` (TUI on
   Linux/macOS; on Windows via the optional `windows-curses` extra, §8),
   `unittest`, `logging`, `socket`, `threading`.
3. **Python ≥ 3.11** (need `tomllib`; 3.11–3.14 supported).
4. **Reliability**: the app is a supervisor — any tunnel/QUIC/NAT loss
   triggers a full re-negotiation (Telegram mode) or re-run (manual mode)
   with exponential backoff, until the operator quits.

### Non-goals

- IPv4 only (socket bound to `0.0.0.0:0`).
- No TURN/relay, no role override mid-tunnel, one local port (client) /
  one target service (server) at a time.
- MVP trust model: fresh self-signed cert per run; humans compare the
  printed SHA-256 fingerprints out of band.

---

## 2. v2 orchestration: divergences from the Rust oracle (by design)

| # | Rust (`main`) | Python (this plan) | Why |
|---|---|---|---|
| D1 | Role **derived** from public-IP comparison (lower = server) | Role **selected by the user at startup** (TUI setup screen / stdin prompt); Telegram handshake **cross-checks** the two declarations; conflict → TUI message + re-selection | Explicit intent beats a derived guess; the operator knows which side exposes the service |
| D2 | Manual exchange is the default; `--telegram` opt-in | **Telegram is the default** when a `[telegram]` table exists (and works); manual is the fallback (automatic on Telegram failure, or forced via `--manual`) | Address copy/paste is the main UX pain; bots are cheap to set up |
| D3 | One-shot run: failure → `error:` + exit 1 | **Supervisor loop**: on tunnel loss, re-negotiate the whole flow (Telegram channel stays alive across attempts), exponential backoff 2 s → 30 s cap, unlimited attempts, `q`/Ctrl-C quits | "Work as reliably as possible, with reconnection" |
| D4 | `PTUN READY <secret>` then `PTUN v1 <addr>` | Same, **plus** a new optional `PTUN ROLE <client|server>` line right after READY (§5.3). Rust peers ignore it (their classifier only matches the `READY `/`v1 ` prefixes — verified against `src/telegram.rs`); a Python peer seeing no ROLE line from the peer falls back to the IP-derived role (legacy) | Carries the declared role without breaking Py↔Rust interop |
| D5 | No setup screen | **Setup screen at startup**: role (client/server) + role-specific setting — server: the service to expose (`ip:port`); client: the local TCP port. Prefilled from `config.toml`, editable in the TUI | Role selection + role-aware config in one place |
| D6 | — | Client always listens on `127.0.0.1:<port>` (localhost-only entry point) — same as Rust, now stated as a product rule | Security by default |

Everything not listed here (STUN encoding/parsing, punch nonce/interval/
timeout, QUIC cert/keep-alive/idle-timeout, bridge half-close semantics,
Telegram getUpdates/staleness/echo rules, hint strings, exit codes) is
ported from the Rust code unchanged.

### The v2 flow (the spec)

```
S0. Start: parse CLI, load config, open TUI (or plain logs).
S1. SETUP (once, or again after a role conflict):
     • role: client | server                (user selects)
     • client → local TCP port (localhost)  (config prefill, editable/prompted)
     • server → service to expose ip:port   (config prefill, editable/prompted)
     • channel: Telegram (default if configured) / manual   (t toggles)
ATTEMPT LOOP (attempt = 1, 2, 3, ...):
T1. [Telegram] Handshake: send `PTUN READY <secret>` + `PTUN ROLE <role>`;
    wait for the peer's fresh READY (required) and ROLE (optional).
     • peer ROLE present  → must be the OPPOSITE of ours, else:
         TUI: "role misconfiguration: both sides are <role>" → back to S1
         (operator re-selects; q quits)
     • peer ROLE absent (legacy Rust peer) → adopt the IP-derived role;
         warn in the TUI if it differs from the user's selection
T2. STUN → our public address (all configured servers, 2 rounds × 3 s).
T3. Address exchange:
     • Telegram: send `PTUN v1 <own>`; wait for the peer's fresh `PTUN v1`
       (offset-based polling ⇒ each attempt only ever sees *new* lines —
       no re-reads of previous attempts' messages)
     • Manual: stdin prompt (first attempt); after 2 consecutive punch
       failures with a cached address, re-prompt (previous value pre-filled)
T4. Hole punching on the shared UDP socket (500 ms interval, 30 s timeout).
T5. Fresh self-signed cert (fingerprint logged) → QUIC handshake on the
    punched socket. Our role decides the side: server accepts, client
    connects. Manual-mode role conflict surfaces here as a repeated
    handshake failure → after 2 attempts the hint says "make sure the peer
    selected the opposite role".
T6. Tunnel bridge:
     • client: TCP listener on 127.0.0.1:<port>; each connection → one
       QUIC bi-stream
     • server: each incoming QUIC stream → TCP connect to the service
    Keep-alive PING every 5 s (both roles).
STABLE until the QUIC connection is lost (timeout, idle, network change)
or the bridge itself dies.
ON LOSS (or any T1–T5 failure):
  • A *stream-level* failure (one localhost client disconnects; the exposed
    service is down → that stream gets a FIN) is NOT a tunnel loss — the
    tunnel keeps serving the other streams.
  • Otherwise: full re-negotiation from T1 (Telegram) or T2+ (manual with
    cached address / re-prompt per the rule above), with exponential
    backoff 2 s → 4 s → 8 s … capped at 30 s; backoff resets after a
    tunnel has been stable ≥ 30 s. Unlimited attempts; the TUI shows the
    attempt number and a "re-negotiating…" state; q / Ctrl-C quits cleanly.
  • The Telegram channel (one getUpdates polling loop) lives for the whole
    app lifetime — attempts reuse it; no per-attempt re-connection to the
    Bot API is needed.
  • If the Telegram handshake (T1) itself times out (peer bot down):
    fall back to the manual prompt for that attempt (Telegram is a
    convenience, never a hard dependency).
```

**Attempt idempotency (both sides retry independently):** on a drop, both
operators' apps re-run the flow at slightly different times. All PTUN lines
are idempotent and order-independent: each side waits for the *first fresh*
peer line of the type it needs (freshness = newer than the attempt start,
enforced by the `offset` cursor + the 600 s staleness filter), duplicates
are ignored, and the READY/ROLE/v1 exchange is symmetric — so the two
attempts interleave without deadlock.

---

## 3. Verified foundation: the `aioquic` spike (done at branch creation)

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
  native**, and the bridge code is byte-for-byte the same shape as Rust.
- **Server-side stream delivery** is the `stream_handler(reader, writer)`
  callback passed to `QuicServer`.
- **Accept-any-cert** (client): aioquic 1.7.2 has no `is_trusted` flag;
  verification is `QuicConfiguration.verify_mode`. We set `ssl.CERT_NONE`
  (the Python equivalent of the Rust `AcceptAnyServerCert`).
- **Peer cert (nice-to-have):** post-handshake,
  `protocol.connection.tls._peer_certificate` holds the peer's
  `x509.Certificate` (private attribute — use defensively, pin the version).
- **Keep-alive:** no built-in interval. We run a task calling
  `await protocol.ping()` every `keep_alive_interval_secs` (0 = off), both
  roles, cancelled when the connection closes.
- `QuicConfiguration.idle_timeout` defaults to 60 s; we set it explicitly.
- **Pin `aioquic>=1.7,<2`**. Fallback if a future release breaks the
  internals we use: rebind a fresh socket to the *same local port* before
  handing it to aioquic (identical 4-tuple ⇒ punched mappings still match).

---

## 4. Architecture

Single `asyncio` process. The pipeline is a set of async steps under a
**supervisor coroutine** (§2 flow); the TUI is a separate **render thread**
fed by a `queue.Queue` — pipeline code only emits events, never calls UI
code (same decoupling as Rust, plus the v2 setup screen and retry state).

```
main()
 ├─ Cli.parse() + Config.load()                (cli.py, config.py)
 ├─ resolve_exchange_mode(cli, cfg)            (telegram default, D2)
 ├─ TUI: queue + render thread (or plain log)  (tui.py, tui_state.py)
 │    └─ S1 SETUP screen: role + role setting + channel (D5)
 ├─ TelegramChannel (long-lived; one getUpdates loop for app lifetime)
 │    └─ Telegram mode only (telegram.py)
 └─ supervisor(attempts):
      ├─ [TG] T1 handshake: READY + ROLE, role cross-check (D1/D4)
      ├─ T2 STUN on the fresh UdpSocket        (stun.py)
      ├─ T3 address exchange (TG v1 / manual prompt)
      ├─ T4 punch(udp, peer)                   (punch.py)
      ├─ T5 cert + QUIC attach on udp          (quic.py)  → fingerprint log
      │    ├─ keep-alive PING task
      │    └─ bridge (tunnel.py)
      │         client: 127.0.0.1:<port> listener → QUIC streams
      │         server: QUIC streams → TCP to service
      └─ on loss → backoff (2→30 s) → next attempt   (D3)
```

### The one UDP socket

`socket.socket(AF_INET, SOCK_DGRAM)`, `bind(("0.0.0.0", 0))`, local port
from `getsockname()`. A **fresh socket per attempt** (the previous attempt's
socket is closed on loss). STUN and punch I/O uses the asyncio-sanctioned
`loop.sock_sendto(sock, ...)` / `loop.sock_recvfrom(sock, ...)` wrappers.
For QUIC we hand the same `sock` object to
`loop.create_datagram_endpoint(..., sock=sock)` — asyncio takes it over
(exactly what aioquic's own `connect()` does). The pipeline is strictly
sequential, so no coroutine touches the socket during handover.

### Module map (Rust → Python)

| Rust (`main` branch) | Python | Notes |
|---|---|---|
| `src/cli.rs` | `p2p_tunnel/cli.py` | argparse; `parse_peer_addr`; prompt loop (now: role prompt + address prompt); `resolve_exchange_mode` (v2, D2) |
| `src/config.rs` | `p2p_tunnel/config.py` | `tomllib`; same keys/defaults; **role-aware validation** (v2, D5): client ⇒ `local_tcp_listen_port` required, server ⇒ `remote_target_addr` required — validated after role selection |
| `src/stun.rs` | `p2p_tunnel/stun.py` | Hand-rolled RFC 5389 (byte-identical layout) |
| `src/punch.rs` | `p2p_tunnel/punch.py` | Same 8-byte nonce, interval/timeout semantics, error text |
| `src/role.rs` | `p2p_tunnel/role.py` | v2: `Role` enum, `check_compatible(ours, theirs)` (raises `RoleConflict`), and the legacy IP-order function kept **for legacy Py↔Rust interop + its 5 oracle tests** |
| `src/quic.rs` | `p2p_tunnel/quic.py` | `cryptography` x509 (P-256, CN `p2p-tunnel`, 30 days); fingerprint = `hex(sha256(DER))`; aioquic attach/connect/accept on the reused socket; keep-alive task |
| `src/tunnel.py` | `p2p_tunnel/tunnel.py` | `bridge_halves` over asyncio streams (TCP and QUIC alike); stream-level vs connection-level failure reporting (v2) |
| `src/telegram.rs` | `p2p_tunnel/telegram.py` | `urllib.request` POST via `run_in_executor`; PTUN protocol v1.1 incl. `PTUN ROLE` (v2, D4); **long-lived channel** (v2, D3) |
| `src/tui.rs` | `p2p_tunnel/tui.py` | curses render thread; **setup screen** (v2, D5); retry-state banner; inline prompt editor; `q`/Esc/Ctrl-C abort, `t` mode toggle; Windows via `windows-curses` extra (§8) |
| `src/tui_state.rs` | `p2p_tunnel/tui_state.py` | Direct port **+ v2 state**: setup phase (role/setting/channel), attempt counter, re-negotiating state, role-conflict message |
| `src/main.rs` | `p2p_tunnel/main.py` | **Supervisor** (v2, D3): the §2 flow, backoff, mode fallback, `error:`/`hint_for()` for hard exits only (operator quit / config errors) |
| `src/lib.rs` | `p2p_tunnel/__init__.py` | Version + docstring |
| — | `p2p_tunnel/__main__.py` | `python -m p2p_tunnel` entry |

### Error handling

- `PuntunnelError(Exception)` base + per-module subclasses
  (`StunError`, `PunchTimeout`, `RoleConflict`, `TelegramError`,
  `QuicSetupError`, …) mirroring the Rust `thiserror` enums, with the same
  user-facing message strings (hint matching depends on them).
- **Two exit classes (v2):**
  - *Hard errors* (config invalid, operator quit) → `error: <msg>` + hint,
    exit 1 (same contract as Rust).
  - *Soft failures* (STUN/punch/handshake/tunnel loss) → **never** exit in
    Telegram mode: the supervisor re-negotiates (D3). In manual mode the
    first failure still offers the Rust behavior (error + exit) **unless**
    the operator is interactive, in which case the supervisor re-prompts
    per §2 (re-prompt rule).
- `hint_for()` substring matches (same four as Rust, plus v2 additions):
  - `"STUN discovery failed"` → connectivity/CGNAT hint
  - `"hole punching timed out"` → stale address / symmetric NAT hint
  - `"QUIC handshake"` → middlebox / peer exited hint; **after 2 failures:
    "make sure both sides selected opposite roles"** (v2)
  - `"is required for the"` → missing config option hint
  - `"role misconfiguration"` → "the two sides must be one client and one
    server — re-select" (v2)
- Logging: stdlib `logging`. Plain mode → stderr, level from
  `P2P_TUNNEL_LOG` env (then `RUST_LOG` for migration), else `--verbose`→
  DEBUG else INFO. TUI mode → logging disabled (the TUI is the single
  source of truth, same as Rust).

### TUI (curses)

- `tui_state.py`: direct port **+ v2**: phases `Setup, Stun, Exchange,
  Punch, Role-check, Quic, Tunnel` (Role-check = the Telegram cross-check
  step), `attempt` counter, `re_negotiating: bool`, `role_conflict:
  str | None`, setup fields (`role`, `client_port`, `server_target`,
  `channel`). `set_phase` auto-completes an earlier stuck Active phase.
- `tui.py`: daemon render thread, curses loop, `nodelay` queue polling +
  `getch()` keys. Panels: header (status color; **red "re-negotiating
  (attempt N)" banner** on loss), phase stepper, setup screen (S1),
  connection panel (own/peer addr, **selected + confirmed roles**,
  fingerprint, local port / target, channel badge), bounded event log,
  bottom prompt line.
- Setup screen keys: `←/→` or `c/s` pick role; `Tab` cycles fields;
  printable keys edit the focused field; `t` toggles channel; `Enter`
  starts (validates per role); `q` quits.
- Runtime prompts (address re-prompt, abort confirmation) reuse the inline
  editor and the `PromptOutcome` contract from `cli.py`.
- Availability: `import curses` — stdlib on Linux/macOS; **absent from
  stock Windows CPython**, provided by the `windows-curses` extra (§8).
  Without it: auto-fall back to plain logs with a one-line hint
  (`for the TUI on Windows: pip install "p2p-tunnel[tui]"`); `--tui` on a
  non-TTY degrades with a warning. Auto-on when stdout is a TTY (Rust rule).
- **Windows-compat constraint (verified):** only classic ncurses calls are
  used (`initscr`, `cbreak`, `noecho`, `keypad`, `nodelay`, `addstr`,
  `getch`, `start_color`, `use_default_colors`, `erase`, `refresh`,
  `curs_set`, `endwin`) — the core that `windows-curses 2.4.2` implements.
  No `curs_set(2)`, no `termattrs`, no ncursesw-only calls. CI runs the
  TUI tests on Windows (drawing under `windows-curses` where available,
  skipped in headless CI).

---

## 5. Wire & behavior spec (parity contract)

### 5.1 STUN (RFC 5389 subset) — `stun.py`

- Binding Request: `msg_type=0x0001`, `msg_len=0`, `magic=0x2112A442`,
  96-bit random transaction ID.
- Response parsing: `msg_type=0x0101` (0x0111 → error code+reason), magic
  verified, transaction ID must match, ignore packets from other
  senders/ports. Attributes scanned in order; skip unknown (pad to 4).
  `ATTR_MAPPED_ADDRESS` (0x0001) and `ATTR_XOR_MAPPED_ADDRESS` (0x0020),
  IPv4 (family 0x01) / IPv6 (0x02); XOR per RFC 5389 §15.
- Discovery: per configured server (default port 19302 when absent), up to
  **2 rounds**, **3 s** per attempt, 512-byte datagram buffer. First valid
  response wins; all exhausted → `StunError` starting with
  `"STUN discovery failed"`.

### 5.2 Role model — `role.py` (v2)

- `Role` enum: `CLIENT`, `SERVER` (`opposite`, `as_str`/`from_str`).
- **Selection (S1):** the user picks; TUI default `client`.
- **Cross-check (T1, Telegram mode):** peer's declared role must be the
  opposite. `check_compatible(ours, theirs)` → `RoleConflict` with a
  message like `"role misconfiguration: both sides selected 'server'"`.
  Supervisor → back to S1 (re-select) after showing the TUI message.
- **Legacy fallback (D4):** no peer ROLE line (Rust peer or old Python) →
  role = IP-derived (below); if that differs from the user's selection →
  TUI warning, the derived role wins (it matches what the Rust peer does).
- **Legacy IP order (kept from Rust, for the fallback + oracle tests):**
  total order over `(family, *octets)` — IPv4 (family 4) sorts before IPv6
  (family 6); same family → byte-wise octet comparison; equal IP → lower
  port wins; the lower endpoint is the **server**.
- **Manual mode:** no cross-check channel — the selection is trusted; a
  wrong pair surfaces as repeated QUIC handshake failures → the role hint
  after 2 attempts (§4).

### 5.3 Telegram signaling — `telegram.py` (PTUN protocol v1.1)

Lines (all plain text, `trim()`-ed, from the peer bot only, subject to
staleness + echo rules below):

| line | status | meaning |
|---|---|---|
| `PTUN READY <secret>` | unchanged | "my process is up and listening" — sent at the start of every attempt |
| `PTUN ROLE <client\|server>` | **new (v1.1)** | declares this side's role — sent right after READY, every attempt |
| `PTUN v1 <ip:port>` | unchanged | announces this side's public address — sent after STUN, every attempt |

- **Sender side:** `send()` posts `sendMessage` to the peer bot's id;
  form-encoded POST, JSON response parsed with stdlib `json`; `ok=false` →
  error with `description`.
- **Receiver side (one long-lived channel, v2):** `getUpdates` long-poll
  loop (`timeout=10`, `allowed_updates=["message"]`, `offset` = highest
  consumed `update_id` + 1) running for the app lifetime. Per attempt, the
  pipeline registers waiters: `wait_ready(secret)`, `wait_role()`,
  `wait_addr()`. The channel classifies each incoming line and satisfies
  the matching waiter (first fresh match wins; duplicates ignored).
- **Freshness/staleness (unchanged rules):** lines with `date` older than
  600 s ignored (`date == 0` / missing accepted — the mock API uses it);
  own-bot echoes ignored (sender id == own bot id from `getMe`); non-bot
  senders ignored; senders other than `peer_bot_id` ignored with a warning.
- **Role cross-check window:** `wait_role()` has a short grace (2 s after
  READY completes) — a ROLE line arriving late (before v1) is still
  recorded; nothing at all ⇒ legacy fallback (§5.2).
- **API base:** default `https://api.telegram.org`, override env
  `PTUN_TELEGRAM_API_BASE` (the mock API test).
- **Failure policy (D2):** any Telegram failure (getMe, send, timeout
  waiting for READY) → warn + the attempt falls back to the manual prompt.
  The channel keeps polling in the background so a later attempt can use
  it again without re-setup.
- **Interop matrix (D4):**

  | we are \ peer is | Python (sends ROLE) | Rust (no ROLE) |
  |---|---|---|
  | **Python** | declared roles; conflict → re-select | IP-derived role on our side (warn if ≠ selection) |
  | **Rust** (oracle) | n/a (Rust ignores ROLE lines) | n/a |

### 5.4 Hole punching — `punch.py` (unchanged from Rust)

- One 8-byte random nonce payload; first packet immediately, then every
  `punch_interval_ms` (default 500, floor 10).
- Wait for any datagram **from exactly `peer_addr`** (ignore everyone
  else). First good packet → success, log count + elapsed.
- No packet within `punch_timeout_secs` (default 30) → error
  `"hole punching timed out …"` including packets sent.
- v2: runs on a **fresh socket per attempt**; the supervisor treats a
  timeout as a soft failure (re-negotiate), and the manual-mode re-prompt
  rule (§2) uses consecutive timeout counts.

### 5.5 QUIC/TLS — `quic.py` (unchanged from Rust, plus v2 notes)

- Fresh self-signed cert per run (per attempt): EC **P-256**, CN
  `p2p-tunnel` (+ SAN), notBefore now, notAfter +30 days. Fingerprint =
  `hex(sha256(DER))` (64 hex chars), logged on both sides.
- Server: `QuicConfiguration(is_client=False, certificate=cert,
  private_key=key, idle_timeout=60)`. Client:
  `QuicConfiguration(is_client=True, server_name="p2p-tunnel",
  verify_mode=ssl.CERT_NONE, idle_timeout=60)`.
- Attach on the reused socket (§3). Keep-alive: `await protocol.ping()`
  every `keep_alive_interval_secs` (default 5; 0 disables), both roles,
  cancellable task.
- Handshake failures: message contains `"QUIC handshake …"` (hint
  matching). **Connection-loss detection (v2):** the supervisor awaits the
  bridge; `ConnectionError`/`asyncio.IncompleteReadError`/QUIC
  idle-timeout close from the transport ⇒ tunnel loss ⇒ re-negotiate. A
  closed stream with a healthy connection ⇒ stream-level only.

### 5.6 Tunnel — `tunnel.py`

- `bridge_halves(r1, w1, r2, w2)`: two copy tasks; EOF →
  `writer.write_eof()`; transport errors propagate; close both sides.
  Generic over asyncio streams → identical code for TCP and QUIC.
- **Client role (D5/D6):** TCP listener on `127.0.0.1:<local_tcp_listen_port>`
  (loopback only). Each accepted TCP connection → one new QUIC bi-stream
  (`create_stream(False)`) → bridge. QUIC connection loss → propagate to
  the supervisor (the listener is torn down, per-connection errors are
  logged).
- **Server role:** each **incoming** QUIC stream (via `stream_handler`) →
  `loop.create_connection` to the configured service (`remote_target_addr`)
  → bridge. Target unreachable/down → warn + close the stream with FIN
  (the localhost client sees EOF), keep serving other streams — **not** a
  tunnel loss.
- Byte counters logged per connection on close (Rust parity).

### 5.7 CLI & config — `cli.py`, `config.py`

**CLI flags (v2):**

| flag | meaning |
|---|---|
| `--config PATH` | TOML config (default `./config.toml`) |
| `--telegram` | force Telegram mode (error with hint if no `[telegram]` table) |
| `--manual`, `--no-telegram` | force manual mode (alias pair) |
| *(none)* | **Telegram if a `[telegram]` table is configured, else manual** (D2) |
| `--tui` / `--no-tui` | TUI on/off (auto: TTY) |
| `--verbose` | debug logging |
| `-V` / `-h` | version / help |

`resolve_exchange_mode(cli, cfg)` is a pure, unit-tested function.

**Config (TOML, `tomllib`):**

| key | type | default | notes |
|---|---|---|---|
| `stun_servers` | `list[str]` | **required, ≥1** | `host` or `host:port`, default port 19302 |
| `punch_interval_ms` | `int` | 500 | floor 10 |
| `punch_timeout_secs` | `int` | 30 | |
| `keep_alive_interval_secs` | `int` | 5 | 0 = off |
| `local_tcp_listen_port` | `int` | — | **required when role = client** (D5); prefills the setup screen |
| `remote_target_addr` | `str` `ip:port` | — | **required when role = server** (D5); the service to expose |
| `[telegram] token` | `str` | — | bot API token |
| `[telegram] peer_bot_id` | `int` | — | peer bot's numeric id |
| `[telegram] timeout_secs` | `int` | 120 | handshake wait |
| `[telegram] secret` | `str` | — | shared secret for `PTUN READY` |

Role-aware validation runs **after** S1 (role known): missing required key
→ setup screen prompts for it (TUI) / stdin prompt (plain), or an
`"… is required for the client role"` hard error when non-interactive.

### 5.8 TUI state machine — `tui_state.py`

Direct port **+ v2** fields (§4). Rust's 4 state tests port unchanged
(phase transitions, active-phase frontier, exchange-mode round-trip,
bounded logs).

---

## 6. Phases

Each phase lands green: unit tests pass, `python -m compileall -q .` clean,
and (from Phase 2 on) the phase's smoke command. Phases 0–1 are done.

### Phase 0 — Branch + scaffold + plan ✅
Branch `python`; Rust files removed; `pyproject.toml` (dep:
`aioquic>=1.7,<2`; **v2 addition: optional extra `tui =
["windows-curses; sys_platform == 'win32'"]`** — applied in Phase 12,
already specified here); package skeleton; PLAN.md v1; PROGRESS.md.

### Phase 1 — Config + CLI parsing ✅
`config.py`, `cli.py` (argparse, `parse_peer_addr`, prompt loop), 26 tests.
**v2 note:** the flag inversion (`--manual`/`--no-telegram`, default
Telegram) and role-aware validation land in Phase 9 as a focused diff on
this code (the original flags stay working until then).

### Phase 2 — STUN
`stun.py`: encode/parse per §5.1, `UdpSocket` helper (bind, `send_to`,
`recv_from` via `loop.sock_*`, local_port, close, `into_raw()` for
handover), `discover_public_addr`. 7 ported tests + live round-trip
against local `tests/nat-sim/stun_server.py`.
**Done-when:** tests green + real `stun.l.google.com:19302` round-trip
prints the public address.

### Phase 3 — Hole punching
`punch.py` per §5.4. 3 ported tests (short timeouts).
**Done-when:** loopback punch succeeds; timeout error text verified.

### Phase 4 — Certificate + QUIC configuration
`quic.py` part 1: `generate_self_signed_cert()` (P-256, CN+SAN, 30 days),
`fingerprint(cert)`, `build_client_config`/`build_server_config`. 4 ported
tests. **Done-when:** green; cert parseable by `openssl x509 -text`.

### Phase 5 — QUIC endpoint on the reused socket
`quic.py` part 2: `attach_client(sock, cfg)`, `attach_server(sock, cfg,
stream_handler)`, `start_keep_alive(protocol, interval)`.
**Deviation (documented):** the Rust project skipped loopback QUIC tests
(quinn socket-ownership ambiguity); with aioquic + `sock=` handover they
are deterministic → loopback attach of both sides, including the
`create_datagram_endpoint(sock=pre_used_sock)` path (STUN datagram through
it first). **Done-when:** loopback handshake green.

### Phase 6 — Client-side bridge
`tunnel.py`: `bridge_halves`, `run_client_side` (127.0.0.1 listener,
per-connection stream). 3 ported bridge tests + loopback e2e (client side
↔ echo over real QUIC). **Done-when:** green.

### Phase 7 — Server-side bridge
`run_server_side`: per incoming stream → TCP connect → bridge; unreachable
target → warn + FIN (stream-level only, v2 semantics). Tests with
`tests/nat-sim/echo_target.py`. **Done-when:** green; `nc` through a
loopback tunnel reaches the echo target.

### Phase 8 — Telegram signaling (moved earlier — it's the default path now)
`telegram.py` per §5.3: `TelegramChannel` (long-lived: `start()` runs the
getUpdates loop; `send()`; `wait_ready/wait_role/wait_addr`), PTUN v1.1
payload build/classify (incl. `PTUN ROLE`), staleness/echo/sender rules,
`PTUN_TELEGRAM_API_BASE` override, blocking HTTP via `run_in_executor`.
Tests: port the Rust `telegram.rs` classify suite (17 tests) against
`tests/telegram/mock_bot_api.py` (unchanged) **+ new**: ROLE line
classify/build, legacy-READY (no role) → `None` role, duplicate-line
idempotency, offset freshness across simulated attempts, getMe/send
error paths. **Done-when:** green under the mock; channel survives a
simulated "attempt 2" with only new updates delivered.

### Phase 9 — Role model + setup + CLI v2 (D1, D2, D5)
- `role.py`: `Role`, `check_compatible`, legacy `role_from_ip_order` +
  the 5 ported Rust role tests + new conflict tests.
- `cli.py`: `--manual`/`--no-telegram`, `--telegram` error-without-table,
  `resolve_exchange_mode`; setup prompts (role → role setting) via the
  existing `PromptOutcome` contract (stdin transport; TUI in Phase 12).
- `config.py`: role-aware validation ("is required for the … role").
- Tests: mode resolution matrix, conflict matrix, legacy fallback,
  role-aware validation. **Done-when:** green; `p2p-tunnel --manual` and
  default-mode behavior verified by hand.

### Phase 10 — Pipeline wiring v1 (the §2 flow, no reconnect yet)
`main.py`: S0–S1 setup → T1 (Telegram handshake + role cross-check, or
manual) → T2 STUN → T3 exchange (TG / prompt) → T4 punch → T5 QUIC →
T6 bridge, on one fresh socket per attempt; hard errors + `hint_for()` +
exit codes; role conflict → message + re-enter S1; stream-level vs
connection-level failure distinction. **Done-when:** two loopback
instances run the full flow in both modes; a forced role conflict shows
the message and re-selection; missing-key errors + hints match the spec.

### Phase 11 — Reconnect supervisor (D3)
Attempt loop around T1–T6; backoff 2→30 s (reset after 30 s stability);
unlimited attempts; TUI retry state + attempt counter; manual-mode
re-prompt rule (2 consecutive punch timeouts); Telegram-failure fallback
to manual per attempt; clean shutdown (`q`/Ctrl-C during backoff, during
handshake, during tunnel); a dropped QUIC connection triggers
re-negotiation without killing the process. **Done-when:** kill-the-tunnel
drill on loopback (close the peer process / drop the socket) → the
surviving side shows "re-negotiating (attempt 2)" and succeeds when the
peer restarts; all shutdown paths exit cleanly.

### Phase 12 — TUI (curses)
- `tui_state.py` (direct port + v2 state + the 4 ported state tests + v2
  event tests: conflict message, re-negotiation banner, setup screen
  folding).
- `tui.py` per §4: render thread, setup screen, stepper, connection panel
  (incl. confirmed roles), log, prompt editor, retry banner, error
  banner + 3 s dwell, 400 ms final paint.
- **Windows:** `pyproject.toml` extra `tui = ["windows-curses;
  sys_platform == 'win32'"]`; runtime detection `import curses` →
  ImportError → plain mode + hint. Only classic ncurses calls (verified
  constraint, §4). **Done-when:** state tests green; real-terminal smoke:
  setup screen, `t` toggle, `q` abort, error/retry banners; Windows CI
  job runs the TUI under `windows-curses` (or skips gracefully).

### Phase 13 — Logging polish
Stdlib logging setup per §4 (env precedence, `--verbose`, TUI-off level),
per-stage messages matching the Rust wording where the step is unchanged.
**Done-when:** side-by-side log comparison with the Rust binary (manual
loopback run) shows equivalent stages/wording for the shared steps.

### Phase 14 — Loopback e2e (new, Python-specific)
`tests/test_e2e_loopback.py`: full pipeline in one process — two roles
(server ↔ echo target), Telegram mode against the mock API (both bots),
STUN against local `stun_server.py`, real QUIC on loopback; assert bytes
round-trip, **then simulate a tunnel drop and assert the supervisor
re-negotiates and round-trips again**.
**Done-when:** green under `unittest`.

### Phase 15 — Real NAT verification
`tests/nat-sim/` driver (two simulated NATs + local STUN + echo target)
drives two `p2p-tunnel` processes through the full §2 flow, including a
**reconnect drill** (kill one process's tunnel, watch re-negotiation via
Telegram); `TESTING.md` with the two-real-machines procedure.
**Done-when:** driver green locally; two-machine run (incl. reconnect)
recorded in PROGRESS.md.

### Phase 16 — Docs, CI, cleanup
- `README.md` as the Python user manual: install (incl.
  `pip install "p2p-tunnel[tui]"` on Windows), **the v2 flow** (setup →
  Telegram → STUN → punch → tunnel → auto-reconnect), config reference,
  Telegram setup (Bot-to-Bot mode, `peer_bot_id`, shared secret), role
  selection + the conflict message, reliability notes (backoff,
  keep-alive, what counts as a drop), TUI, troubleshooting, security note
  (MVP trust model, loopback-only client listener), Py↔Rust interop note
  (legacy role fallback).
- `.github/workflows/ci.yml`: matrix 3.11–3.14 × (linux, windows, macos),
  `pip install -e .[tui]` on Windows, `python -m unittest discover -s
  tests -v`, `python -m compileall -q .`; network-touching tests skipped
  offline.
- `py.typed`, final PROGRESS.md entry, tag `v0.1.0-py`.
- **Done-when:** CI green; README matches actual behavior.

---

## 7. Test strategy

- **`unittest` only** (stdlib; `IsolatedAsyncioTestCase` for async). No
  pytest, no test-only dependencies.
- Tree mirrors the Rust one:
  ```
  tests/
  ├── test_cli.py test_config.py test_stun.py test_punch.py test_role.py
  ├── test_quic.py test_tunnel.py test_telegram.py
  ├── test_tui_state.py test_tui_events.py
  ├── test_e2e_loopback.py
  ├── nat-sim/        (reused: stun_server.py, echo_target.py,
  │                    probe_client.py + new nat_sim driver)
  └── telegram/mock_bot_api.py   (reused unchanged)
  ```
- Rust test parity: all 46 Rust tests have a Python counterpart (mapped
  per phase above) — the 5 role tests now cover the *legacy*
  IP-ordering function (kept for interop), plus new v2 tests: mode
  resolution, role conflict, PTUN ROLE, supervisor backoff/re-negotiation
  (loopback), setup-screen state folding.
- Network-touching tests (real STUN) are `skipIf` on reachability so CI
  stays hermetic. Concurrency tests scale timeouts down (30 s → 2 s).

## 8. Risks & mitigations

| Risk | Mitigation |
|---|---|
| aioquic API drift (`QuicServer` internals, `sock=` handover) | Pin `aioquic>=1.7,<2`; all aioquic contact isolated in `quic.py`; fallback = rebind fresh socket to same local port (§3) |
| asyncio socket handover (sock_recvfrom → create_datagram_endpoint on same fd) | Phase 5 test uses a pre-used socket; Phase 14 covers e2e |
| `curses` absent on Windows | Verified: `windows-curses 2.4.2` (cp311–cp314 wheels) installs the stdlib `_curses`/`_curses_panel` extensions → `import curses` works; optional extra with `sys_platform` marker; auto-fallback to plain logs; CI on Windows |
| windows-curses API gaps | Only classic ncurses core used (§4 constraint); TUI tests run in Windows CI |
| Reconnect races (both sides retry independently) | §2 idempotency argument: offset-fresh waiters, first-match wins, symmetric exchange; Phase 11/14/15 drills (incl. staggered restarts) |
| Pure-Python QUIC throughput < Rust quinn | Acceptable for MVP use cases (SSH, file transfer, shells); documented; TLS crypto is C (`cryptography`) |
| Long-lived Telegram channel drifts (bot API rate limits, token revoked) | 10 s long-poll is gentle; failures degrade to manual fallback per attempt; `getUpdates` is stateless (offset) so restarts are lossless |
| Python 3.14 asyncio quirks | CI matrix includes 3.14; local dev on 3.14.8 |
| Fork divergence from the Rust oracle | Rust `main` frozen; orchestration divergences are listed exhaustively in §2; wire-level behavior still matches |

## 9. Verification (run at every phase gate)

```sh
python3 -m venv .venv && . .venv/bin/activate
pip install -e .
python -m compileall -q p2p_tunnel tests
python -m unittest discover -s tests -v
p2p-tunnel --help && p2p-tunnel -V
```
