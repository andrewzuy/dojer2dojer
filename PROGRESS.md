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
