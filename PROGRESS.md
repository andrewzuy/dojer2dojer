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
