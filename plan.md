# PLAN — v2 orchestration for Rust `p2p-tunnel` (feature completion)

Status: **new**. The `main` branch (frozen wire reference at `f2dc2a4`) is
functionally complete through Phase 11 (logging polish) and is about to run
its Phase 12 real-NAT test. This plan adds the **v2 orchestration** the Python
rewrite (`python` branch) was designed around — a reconnect **supervisor**,
**role selection/cross-check**, **Telegram-first defaults**, and the
`PTUN ROLE` interop line — porting the *same product decisions* into the Rust
codebase. The wire-level behavior (STUN, punch, QUIC, Telegram classify,
tunnel bridge, legacy IP-derived role) stays **unchanged**; only orchestration
diverges, and here this document wins (same contract as `python/PLAN.md`).

> **HARD RULE (2026-11-15, absolute):** every command executed on this project
> — tests, builds, anything — MUST be restricted to at most 5 minutes (300 s)
> (`cargo test` batches / harness `timeout 300`). Never run anything
> unrestricted. See `PROGRESS.md` 2026-11-15 entry (5 h 58 m incident).

---

## 1. Goals

1. **Feature parity-plus** with the current Rust tool, plus the v2
   orchestration (§2): startup **role selection**, **Telegram-first defaults**,
   **role conflict detection**, and automatic **re-negotiation on tunnel loss**
   (a supervisor instead of a one-shot run).
2. **Zero new runtime dependencies** for the core. Use only what is already in
   `Cargo.toml`: `tokio`, `quinn`, `rcgen`, `sha2`, `hex`, `rand`, `clap`,
   `serde`, `toml`, `tracing`, `anyhow`, `thiserror`, `ratatui`, `crossterm`.
   (The Python branch reached for `aioquic`; the Rust path reuses `quinn` and
   the existing modules — no dependency drift, no new lockfile entries.)
3. **Python ≥ 3.11 analog → Rust ≥ current MSRV unchanged.** No toolchain
   bumps; CI matrix already covers the supported platforms.
4. **Reliability:** the app becomes a **supervisor** — any tunnel/QUIC/NAT loss
   triggers a full re-negotiation (Telegram channel stays alive across
   attempts) with exponential backoff, until the operator quits.

### Non-goals

- IPv4 only (unchanged).
- No TURN/relay, no role override *mid-tunnel*, one local port / one target
  service at a time.
- MVP trust model unchanged (fresh self-signed cert per run; humans compare
  printed SHA-256 fingerprints out of band).

---

## 2. v2 orchestration: divergences from the current `main` (by design)

The current `main` is a **one-shot** run: `config → STUN → print addr → prompt
peer → punch → role → certs → QUIC → tunnel`, failure → `error:` + exit 1.
Everything below is a deliberate departure.

| # | Current `main` | Rust v2 (this plan) | Why |
|---|---|---|---|
| D1 | Role **derived** from public-IP comparison (lower = server) | Role **selected by the user at startup** (TUI setup screen / stdin prompt); Telegram handshake **cross-checks** the two declarations; conflict → TUI message + re-selection | Explicit intent beats a derived guess; the operator knows which side exposes the service |
| D2 | Manual exchange is the default; `--telegram` opt-in | **Telegram is the default** when a `[telegram]` table exists (and works); manual is the fallback (automatic on Telegram failure, or forced via `--manual`) | Address copy/paste is the main UX pain; bots are cheap to set up |
| D3 | One-shot run: failure → `error:` + exit 1 | **Supervisor loop**: on tunnel loss, re-negotiate the whole flow (Telegram channel stays alive across attempts), exponential backoff 2 s → 30 s cap, unlimited attempts, `q`/Ctrl-C quits | "Work as reliably as possible, with reconnection" |
| D4 | No setup screen | Same handshake, **plus** a new optional `PTUN ROLE <client\|server>` line right after READY; a Rust peer ignoring it stays interoperable (classifier only matches `READY`/`v1`) | Carries the declared role without breaking Rust↔Python interop |
| D5 | No setup screen | **Setup screen at startup**: role (client/server) + role-specific setting — server: the service to expose (`ip:port`); client: the local TCP port. Prefilled from `config.toml`, editable in the TUI | Role selection + role-aware config in one place |
| D6 | — | Client always listens on `127.0.0.1:<port>` (localhost-only entry point) — same as current, now stated as a product rule | Security by default |

Everything not listed here (STUN encoding/parsing, punch nonce/interval/
timeout, QUIC cert/keep-alive/idle-timeout, bridge half-close semantics,
Telegram getUpdates/staleness/echo rules, hint strings, exit codes) is
ported from the current Rust code unchanged.

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
     • peer ROLE absent (legacy Python/Rust peer) → adopt the IP-derived role;
         warn in the TUI if it differs from the user's selection
T2. STUN → our public address (all configured servers, 2 rounds × 3 s).
T3. Address exchange:
     • Telegram: send `PTUN v1 <own>`; wait for the peer's fresh `PTUN v1`
       (offset-based polling ⇒ each attempt only ever sees *new* lines)
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
    cached address / re-prompt per the rule above), with exponential backoff
    2 s → 4 s → 8 s … capped at 30 s; backoff resets after a tunnel has been
    stable ≥ 30 s. Unlimited attempts; the TUI shows the attempt number and a
    "re-negotiating…" state; q / Ctrl-C quits cleanly.
  • The Telegram channel (one getUpdates polling loop) lives for the whole
    app lifetime — attempts reuse it; no per-attempt re-connection to the
    Bot API is needed.
  • If the Telegram handshake (T1) itself times out (peer bot down):
    fall back to the manual prompt for that attempt (Telegram is a
    convenience, never a hard dependency).
```

**Attempt idempotency (both sides retry independently):** on a drop, both
operators' apps re-run the flow at slightly different times. All PTUN lines are
idempotent and order-independent: each side waits for the *first fresh* peer
line of the type it needs (freshness = newer than the attempt start, enforced
by the `offset` cursor + the 600 s staleness filter), duplicates are ignored,
and the READY/ROLE/v1 exchange is symmetric — so the two attempts interleave
without deadlock.

---

## 3. Module map (current Rust module → v2 responsibility)

| Module | Current role | v2 additions |
|---|---|---|
| `src/role.rs` | `Role` enum + legacy `role_from_ip_order` (for interop) | Add `check_compatible(ours, theirs) -> Result<(), RoleConflict>`; keep legacy IP-order fn + its oracle tests |
| `src/telegram.rs` | PTUN v1 classify/send + one-shot exchange | `PTUN ROLE` line build/classify; **long-lived channel** (`start()` runs one getUpdates loop for the app lifetime, reused across attempts); `wait_ready/wait_role/wait_addr` with short ROLE grace window |
| `src/main.rs` | one-shot pipeline (`run_pipeline`) + render loop | **Supervisor** (`supervisor(attempts)`) wrapping the pipeline; backoff; mode fallback; `q`/Ctrl-C during handshake/backoff/tunnel |
| `src/config.rs` | keys/defaults + basic validation | **role-aware validation**: client ⇒ `local_tcp_listen_port` required, server ⇒ `remote_target_addr` required — validated after role selection |
| `src/cli.rs` | argparse + prompt loop | `--manual`/`--no-telegram` alias pair; `--telegram` errors without `[telegram]` table; `resolve_exchange_mode(cli, cfg)` pure fn; setup prompts (role → role setting) via `PromptOutcome` (stdin; TUI in Ph 12) |
| `src/tui.rs` / `src/tui_state.rs` | lifecycle render + state | setup screen (S1), retry-state banner, attempt counter, confirmed roles, role-conflict message |

---

## 4. Phases

Each phase lands green: unit tests pass, `cargo check`/`cargo clippy` clean,
and (from Phase 2 on) the phase's smoke command. **Phases 0–11 are already
done** on `main`; the numbering below continues and only the *new* phases are
listed.

### Phase 0 — Role model + conflict detection (§2 D1/D4)
`src/role.rs`: `check_compatible(ours, theirs) -> Result<(), RoleConflict>`,
`RoleConflict` in `thiserror`; keep `role_from_ip_order` + the 5 ported oracle
tests. `Role::opposite()` / `as_str()` / `from_str()` already exist — verify
they satisfy the new call sites.
**Done-when:** conflict raised on same-side pair; legacy IP-order tests still
pass; `cargo check` clean.

### Phase 1 — Telegram `PTUN ROLE` + long-lived channel (§2 D2/D4)
`src/telegram.rs`:
- PTUN protocol **v1.1**: add `PTUN ROLE <client|server>` — build in the
  handshake payload, classify incoming lines, `PTUN ROLE` → `None` role when
  absent (legacy), duplicate-line idempotency, offset freshness across
  simulated attempts.
- **Long-lived channel**: `TelegramChannel::start()` runs the single
  `getUpdates` loop (`timeout=10`, `allowed_updates=["message"]`, `offset`
  cursor, staleness 600 s, echo/peer-sender filtering) for the app lifetime;
  `send()` posts `sendMessage` (form POST, JSON, `ok=false` → error +
  `description`). Per-attempt waiters: `wait_ready(secret)`, `wait_role()`
  (2 s grace after READY), `wait_addr()`.
- `PTUN_TELEGRAM_API_BASE` override; HTTP via `reqwest` (already a dep).
- Tests: port the Rust `telegram.rs` classify suite + new ROLE/legacy/
  idempotency/freshness tests against `tests/telegram/mock_bot_api.py`
  (already present) — but as Rust tests using a local HTTP mock (see §7).
**Done-when:** ROLE build/classify round-trips; long-lived channel survives a
simulated "attempt 2" with only new updates delivered; no new deps.

### Phase 2 — Role-aware config + CLI mode resolution (§2 D2/D5)
- `src/config.rs`: role-aware validation — after role is known, missing
  `local_tcp_listen_port` (client) or `remote_target_addr` (server) is a hard
  error `"… is required for the <role> role"`.
- `src/cli.rs`: `--manual`/`--no-telegram` alias pair; `--telegram` errors
  with a hint if no `[telegram]` table; `resolve_exchange_mode(cli, cfg)` pure,
  unit-tested.
- Tests: mode-resolution matrix, role-aware validation, conflict matrix.
**Done-when:** `p2p-tunnel --help`, `--manual`, and default-mode parsing all
verified; `resolve_exchange_mode` tests green.

### Phase 3 — Pipeline wiring v1: supervisor without reconnect yet (§2 flow)
`src/main.rs`: S0–S1 setup → T1 (Telegram handshake + role cross-check, or
manual) → T2 STUN → T3 exchange (TG / prompt) → T4 punch → T5 QUIC → T6
bridge, on **one fresh socket per attempt**; hard errors + `hint_for()` + exit
codes; role conflict → message + re-enter S1; stream-level vs connection-level
failure distinction. The **supervisor loop** is introduced here but does a
**single** attempt per invocation first (reconnect lands in Phase 5).
**Done-when:** two loopback instances run the full flow in both modes; a
forced role conflict shows the message and re-selection; missing-key errors +
hints match the spec; `cargo clippy` clean.

### Phase 4 — Reconnect supervisor + backoff (§2 D3)
Wrap the pipeline in `supervisor(attempts)`:
- Attempt loop with exponential backoff **2 s → 30 s** (2→4→8→… capped at 30 s);
  backoff **resets** after a tunnel has been stable ≥ 30 s. Unlimited attempts.
- Telegram channel stays alive across attempts (reuses the long-lived channel
  from Phase 1); manual-mode re-prompt rule (2 consecutive punch timeouts,
  previous value pre-filled).
- Telegram-failure fallback to the manual prompt per attempt.
- Clean shutdown (`q`/Ctrl-C) during backoff, during handshake, during tunnel;
  a dropped QUIC connection triggers re-negotiation **without** killing the
  process.
- TUI retry state + attempt counter; manual-mode re-prompt state.
**Done-when:** kill-the-tunnel drill on loopback (close the peer process / drop
the socket) → the surviving side shows "re-negotiating (attempt 2)" and
succeeds when the peer restarts; all shutdown paths exit cleanly.

### Phase 5 — TUI: setup screen + retry state (§2 D5)
- `src/tui_state.rs`: phases `Setup, Stun, Exchange, Punch, Role-check, Quic,
  Tunnel` (Role-check = the Telegram cross-check step), `attempt` counter,
  `re_negotiating: bool`, `role_conflict: Option<String>`, setup fields
  (`role`, `client_port`, `server_target`, `channel`). `set_phase` auto-
  completes an earlier stuck Active phase.
- `src/tui.rs`: daemon render thread, curses/ratatui loop, panels: header
  (status color; **red "re-negotiating (attempt N)" banner** on loss), phase
  stepper, setup screen (S1), connection panel (own/peer addr, **selected +
  confirmed roles**, fingerprint, local port / target, channel badge), bounded
  event log, bottom prompt line; retry banner + error banner + 3 s dwell,
  400 ms final paint.
- Setup screen keys: `←/→` or `c/s` pick role; `Tab` cycles fields; printable
  keys edit the focused field; `t` toggles channel; `Enter` starts (validates
  per role); `q` quits.
**Done-when:** real-terminal smoke: setup screen, `t` toggle, `q` abort,
error/retry banners; state unit tests green.

### Phase 6 — Logging polish + interop docs (§2 + Phase 13 analog)
- Per-stage messages for the new steps matching Rust wording where unchanged.
- Side-by-side log comparison (manual loopback run) shows equivalent stages.
- README update: the **v2 flow** (setup → Telegram → STUN → punch → tunnel →
  auto-reconnect), role selection + conflict message, reliability notes
  (backoff, keep-alive, what counts as a drop), Telegram setup, Py↔Rust
  interop note (legacy role fallback), security note (loopback-only client).
- `.github/workflows/ci.yml`: network-touching tests `skipIf` on reachability;
  final PROGRESS.md entry.
**Done-when:** log comparison done; README matches actual behavior; CI green.

---

## 5. Design notes for Rust authors

### The supervisor shape
The current `main` runs `run_pipeline(...)` once. v2 wraps it:

```
main()
 ├─ Cli.parse() + Config.load()
 ├─ TUI: queue + render thread (or plain log)
 ├─ TelegramChannel::start()          // ONE long-lived getUpdates loop
 └─ supervisor(attempts):
      loop {
          attempt += 1
          pipeline attempt 1..6 (T1..T6) on a fresh UdpSocket
          match outcome {
              Stable     => sleep(stability), then possibly restart backoff
              TunnelLoss => backoff(dur); if interrupted => quit; continue
              HardError  => error: <msg> + hint, exit 1
          }
      }
```

Keep `run_pipeline` intact (it becomes the per-attempt body). The supervisor
owns the **backoff clock**, the **attempt counter** (published to the render
loop), and the **Telegram channel lifetime**. Because all PTUN lines are
idempotent/order-independent, retrying the pipeline at a different moment than
the peer cannot deadlock.

### Fresh socket per attempt
A fresh `tokio::net::UdpSocket` bound to `0.0.0.0:0` per attempt; the previous
attempt's socket is closed on loss. STUN/punch use the socket; `quinn` takes
ownership via `.into_std()` for the QUIC handshake (unchanged socket-handover
contract). The supervisor closes the attempt's endpoint on tunnel loss.

### Role cross-check timing
`wait_role()` has a short grace (2 s after READY completes) — a ROLE line
arriving late (before v1) is still recorded; nothing at all ⇒ legacy IP-derived
fallback (§2 D4). Manual mode has no cross-check channel — a wrong pair
surfaces as repeated QUIC handshake failures → the role hint after 2 attempts.

### No new dependencies
Reuse `reqwest` (already a `Cargo.toml` dep, currently used for Telegram HTTP)
and the existing crypto/quic stack. Do **not** add `aioquic` or bump the
toolchain. If `reqwest`'s blocking `run_in_executor`-style usage needs an
async alternative, prefer `tokio`'s runtime (already present) rather than a new
dep.

---

## 6. Verification (run at every phase gate)

```sh
cargo check
cargo clippy --all-targets -- -D warnings
cargo test                       # batched; each batch < 300 s
# smoke (from Phase 3 on):
cargo run -- --help && cargo run -- -V
```

Per the HARD RULE, keep every `cargo test` batch under 300 s; long suites run
in per-module batches.
