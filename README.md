# p2p-tunnel

[![CI](https://github.com/andrewzuy/dojer2dojer/actions/workflows/ci.yml/badge.svg)](https://github.com/andrewzuy/dojer2dojer/actions/workflows/ci.yml)

A small Rust CLI that lets two machines behind NATs reach each other's
**private TCP services** — no ports to open, no relay server, no account.

The flow is: **you pick who serves** (client/server, with a live setup screen),
both sides discover their public addresses, exchange them automatically over
Telegram (manual prompt as fallback), punch through the NATs, and keep the
tunnel alive — re-negotiating automatically if it drops.

Type one address into the other machine, and a normal TCP tool (`ssh`,
`nc`, `curl`, …) works as if the two machines were on the same LAN.

- **STUN** (RFC 5389, hand-rolled) discovers each machine's public `ip:port`
- **Simultaneous UDP hole punching** opens the NAT hole
- **QUIC / TLS 1.3** (quinn) carries an encrypted, reliable byte pipe over the hole
- A **TCP↔QUIC stream bridge** turns the pipe into ordinary TCP connections
- A **live TUI** (ratatui + crossterm) visualizes the whole lifecycle — phase stepper, connection diagram, and scrolling event log — and auto-enables on any real terminal

```
┌────────────────────────┐                         ┌────────────────────────┐
│  Machine A (laptop)    │                         │  Machine B (home box)  │
│                        │  STUN servers (UDP)     │                        │
│  app ──TCP──► 127.0.0.1│◄────────────────────────│  127.0.0.1:22 ── sshd  │
│          :12345        │                         │                        │
│   (client role)        │                         │   (server role)        │
│  ┌───────────────────┐ │                         │ ┌───────────────────┐  │
│  │  QUIC (quinn)     │ │════ punched UDP hole ═══│ │  QUIC (quinn)     │  │
│  └─────────▲─────────┘ │                         │ └─────────▲─────────┘  │
│            │           │                         │           │            │
│  ┌─────────┴─────────┐ │   1. STUN   2. punch    │  ┌─────────┴─────────┐ │
│  │  ONE UDP socket   │ │   3. QUIC handshake     │  │  ONE UDP socket   │ │
│  │  STUN→punch→QUIC  │ │   4. TCP↔QUIC bridges   │  │  STUN→punch→QUIC  │ │
│  └───────────────────┘ │                         │  └───────────────────┘ │
└────────────────────────┘                         └────────────────────────┘
```

**The killer detail:** each side creates **one UDP socket up front and reuses
it for the entire session** — STUN discovery, hole punching, and finally the
QUIC endpoint (quinn takes ownership of it). Creating a new socket would get a
new NAT mapping and close the freshly-punched hole, so this reuse is what
makes the design work.

---

## Table of contents

1. [How it works](#how-it-works)
2. [Which side exposes the service](#which-side-exposes-the-service)
3. [Requirements](#requirements)
4. [Getting a binary](#getting-a-binary) and [Building from source](#building-from-source)
5. [Quick start (two machines, SSH to a home server)](#quick-start)
6. [Telegram address exchange (the default)](#telegram-address-exchange-the-default)
7. [Configuration reference](#configuration-reference-configtoml)
8. [CLI reference](#cli-reference)
9. [Examples](#examples)
10. [Security model](#security-model)
11. [Troubleshooting](#troubleshooting)
12. [Limitations](#limitations)
13. [Development](#development)
14. [License](#license)

---

## How it works

Everything below happens on **both** machines, in the same order. The setup
screen appears first, then the exchange, and each side ends with the same
story: **you pick who serves, the two sides prove they're up, discover their
addresses, cross-check roles, punch, handshake, and tunnel — retrying
automatically if it drops.**

### 1. Startup setup

The app asks for three things — the role, the setting for that role, and the
address-exchange channel — and validates them before anything else happens.

- **Role** (`client` | `server`): `--role` flag → `role` config key →
  interactive prompt. The two sides must disagree (opposite roles); the
  exchange below makes that enforceable.
- **Setting** — the one thing this machine does with the tunnel:
  - **client**: `127.0.0.1:<local_tcp_listen_port>` — the local port the
    tunnel is offered on.
  - **server**: `<remote_target_addr>` — the private service on this machine
    that tunneled traffic is delivered to.
- **Channel** — how the peer address is exchanged (Telegram or manual; see
  below).

The setting is validated at setup time (a reachable port number, a parseable
`ip:port`), so a config mistake surfaces immediately — not after the punch.

### 2. Readiness handshake + STUN discovery (Telegram mode)

1. **Readiness handshake.** Before anything is sent, each bot sends the peer
   a `PTUN READY <secret>` line — and a `PTUN ROLE <client|server>` line
   declaring its role — and waits for the peer's. This proves the peer bot
   is up and listening *before* anything else; the shared secret is the only
   cross-machine credential the handshake needs. Any failure here falls back
   to the manual prompt.
2. **STUN discovery.** A raw RFC 5389 **Binding Request** is sent from THE
   socket to each configured STUN server (manual implementation — no STUN
   crate, because the socket must stay under our control for the later
   phases). Each server gets up to 3 s, and the whole list is tried twice.
   The response's `XOR-MAPPED-ADDRESS` attribute tells us the public
   `ip:port` the rest of the internet sees for this socket.

Manual mode (`--manual`, or no usable `[telegram]` table) skips the handshake
and goes straight to STUN.

### 3. Peer address exchange — announce + wait

When a usable `[telegram]` table is configured, the two sides exchange
addresses automatically — **no copy/paste**:

1. Each bot announces its public address as `PTUN v1 <ip:port>` to the peer
   bot.
2. Each side waits for the peer's announcement (bounded by `timeout_secs`,
   default 120 s). A stale line older than 10 minutes is ignored, and the
   own-echo is dropped, so nothing re-processed or replayed is accepted.
3. If the timeout fires or Telegram is unreachable, the app logs the reason
   and drops back to the **manual prompt** (type the peer's address).

Manual mode — `--manual`, or no usable table — is the unchanged fallback:
each side prints its address, you exchange them out-of-band, and each enters
the other's into the prompt (validated, re-prompted on bad input).

> **Addresses are session-scoped.** The port (and sometimes the IP) changes
> every time the process runs, and the NAT mapping goes away when the process
> exits or the binding expires. There is no persistent "tunnel address" —
> exchange a fresh address for every session.

### 4. Role cross-check (Telegram mode)

As part of the readiness handshake each side declared its role. After the
address exchange, the app cross-checks the two declarations: if they disagree
— the same role on both sides, which can never tunnel — the app says so
loudly (`role misconfiguration: …`) and stops *at startup*, re-selecting the
setup screen instead of silently burning a punch cycle. A matching pair
proceeds. The choice of role is never derived from addresses — you picked it
at setup, and the cross-check makes sure both sides meant the same thing.

### 5. UDP hole punching

Both sides repeatedly send a small UDP packet (a random 8-byte session
nonce) to the peer's public address, every `punch_interval_ms`
(default 500 ms). The moment a packet **from the peer's exact address**
arrives, the punch has succeeded on that side; anything from other senders is
ignored. Packets are sent for up to `punch_timeout_secs` (default 30 s).
Because both sides punch at the same time, typical cone NATs open within a
few seconds of both processes starting.

### 6. Self-signed certificate + QUIC handshake

A fresh **ECDSA P-256 self-signed certificate** (CN `p2p-tunnel`) is
generated in memory once the role is known. The server presents it; the client accepts
*any* certificate — see the [security model](#security-model) for what that
means in practice. **Both sides log the certificate's SHA-256 fingerprint** so
the two humans can compare it out-of-band, exactly like an SSH host-key
fingerprint.

The punched UDP socket is then handed to quinn, which takes ownership and
performs the TLS 1.3 / QUIC handshake over it.

### 7. TCP↔QUIC stream bridge

- **Client role:** a local TCP listener on `127.0.0.1:<local_tcp_listen_port>`
  accepts connections. Each accepted connection gets its **own bidirectional
  QUIC stream**, so several concurrent connections (multiple `ssh` sessions)
  are independent.
- **Server role:** each incoming QUIC stream gets its **own TCP connection**
  to the configured `remote_target_addr`.

Bytes are copied in both directions with **half-close semantics**: EOF in one
direction shuts down only that direction — the other keeps flowing until it
sees its own EOF. (This is what makes patterns like `echo x | ssh host cat`
work instead of dying.) If the server's target is unreachable, the client
sees a clean EOF rather than hanging.

### Reconnect behavior

The tunnel is a **reconnect supervisor**, not a one-shot process. When the
QUIC connection drops — or a STUN/punch/handshake step fails after the tunnel
starts — the supervisor backs off (2 s, 4 s, 8 s … capped at 30 s, full jitter, and
the backoff clock resets if the tunnel stayed up at least 30 s) and re-negotiates
everything from scratch: fresh STUN, fresh exchange, fresh punch, fresh
handshake, fresh tunnel. Each attempt gets a new NAT mapping and a new peer
address — nothing is reused. The escalation status line (`tunnel dropped —
retrying in …`) explains what is happening without interrupting the pane.

User abort (`q` / Esc / Ctrl-C) always exits cleanly. Setup errors and
structural errors (e.g. the port is already in use) exit with a non-zero
code and an actionable hint.

---

## Which side exposes the service

Roles are now **user-selected**, not derived from addresses, so the direction
is exactly what you configured:

- The **client** side offers the local port: anything dialed to
  `127.0.0.1:<local_tcp_listen_port>` on that machine is forwarded to the
  peer's target.
- The **server** side exposes the private service: anything tunneled arrives
  at `remote_target_addr` on that machine.

The two sides must choose **opposite** roles. The app enforces this at startup
(in Telegram mode it cross-checks the peer's declared role and refuses to
proceed on a conflict), so both sides always agree on who serves — there is
no longer an "it depends on the public IP order" surprise.

**Tip that removes the fiddling:** put both keys in *every* machine's config —
`local_tcp_listen_port` (the port this machine will offer) and
`remote_target_addr` (the private service on this machine). Each side only
reads the key matching its chosen role, so you never need to predict which
role you'll get — you choose it at the setup screen.

---

## Requirements

- **Rust** (edition 2024; tested with cargo 1.93) — or grab a
  [CI-built static Linux binary](#getting-a-binary)
- **Outbound UDP** to a STUN server (default config uses Google/Cloudflare)
  and to the peer's public address
- **Two machines whose NATs are not symmetric** (see
  [Limitations](#limitations))
- For real use: a way to compare the two certificate fingerprints out-of-band
  (any chat) — the one comparison the tunnel does not automate

## Getting a binary

**Prebuilt binaries** are published on the
[GitHub Releases page](https://github.com/andrewzuy/dojer2dojer/releases).
Each release contains:

| Asset | Platform |
| --- | --- |
| `p2p-tunnel-vX.Y.Z-x86_64-unknown-linux-musl` | Linux x86_64 (static — no dependencies) |
| `p2p-tunnel-vX.Y.Z-aarch64-unknown-linux-musl` | Linux ARM64 (static — Raspberry Pi & co.) |
| `p2p-tunnel-vX.Y.Z-aarch64-apple-darwin` | macOS (Apple Silicon) |
| `p2p-tunnel-vX.Y.Z-x86_64-apple-darwin` | macOS (Intel) |
| `p2p-tunnel-vX.Y.Z-x86_64-pc-windows-msvc.exe` | Windows x86_64 |
| `SHA256SUMS` | SHA-256 checksums for the above |

The Release workflow (`.github/workflows/release.yml`) builds all of these
and publishes them automatically **when a `v*` tag is pushed** — or on demand
via *Actions → Release → Run workflow* (enter the tag to publish). Creating a
release is just:

```sh
git tag v0.1.0 && git push origin v0.1.0
```

Verify a download before running it:

```sh
sha256sum -c SHA256SUMS --ignore-missing
```

The Linux builds are fully static (musl) — no shared-library surprises on
minimal distros:

```sh
# e.g. on a bare Debian/Alpine box:
chmod +x p2p-tunnel-v0.1.0-x86_64-unknown-linux-musl
./p2p-tunnel-v0.1.0-x86_64-unknown-linux-musl
```

## Building from source

```sh
cargo build --release
# binary: target/release/p2p-tunnel
```

The binary is self-contained (no runtime dependencies beyond the usual
libc/OS crypto).

---

## Quick start

Goal: from a laptop (behind any NAT), `ssh` into your home server's private
SSH — no router config, no public IP requirement, no relay.

### Step 1 — build on both machines

`cargo build --release` (or use the static CI binary on Linux).

### Step 2 — write the config on both machines

Pick the roles first (both sides must be opposite), then write the config.

**Home box** — exposes SSH (server role):

```toml
stun_servers = [
    "stun.l.google.com:19302",
    "stun.cloudflare.com:3478",
]

role = "server"

# The private service on THIS box to expose. Here: SSH on loopback.
remote_target_addr = "127.0.0.1:22"
```

**Laptop** — consumes the tunnel (client role):

```toml
stun_servers = [
    "stun.l.google.com:19302",
    "stun.cloudflare.com:3478",
]

role = "client"

# The port the laptop will offer, e.g. ssh -p 12345 user@127.0.0.1
local_tcp_listen_port = 12345
```

(Role can also be set per-run with `--role`, overriding the config key. If
neither is given, you get the role picker at startup.
See [Which side exposes the service](#which-side-exposes-the-service) and the
[Configuration reference](#configuration-reference-configtoml) for every key.)

### Step 3 — run on both machines

```sh
# home box
./target/release/p2p-tunnel
# laptop
./target/release/p2p-tunnel
```

Each machine shows the setup screen (role + setting + channel). With a
usable `[telegram]` table the address exchange is automatic — no flag needed.
With `--manual` (or no usable table) each machine prints its public address;
exchange them out-of-band and enter each one into the other's prompt:

```text
# home box                                        # laptop
Your public address is: 93.184.216.34:51000       Your public address is: 203.0.113.7:48000
Give it to the other party, then enter
their public address below.
Enter peer's public address (ip:port):            Enter peer's public address (ip:port):
203.0.113.7:48000                                 93.184.216.34:51000
```

### Step 4 — watch both sides connect

Within seconds (usually well under the 30 s punch timeout) both sides log
success. The log is the same story on both machines:

```text
role selected — setup complete                 # role + setting + channel
discovered public address: 93.184.216.34:51000
exchanging readiness with the peer bot over Telegram…   # Telegram mode
hole punched: packet received from peer  elapsed_ms=1412  sent=3
QUIC endpoint ready
QUIC connection established            # client
QUIC connection accepted                # server
tunnel is up — traffic is flowing
```

When the tunnel is up, both sides log the certificate fingerprint and the
local listener line (the client) / the target (the server):

```text
# laptop (client role)
  tunnel client listening — connect to 127.0.0.1:12345 (e.g. ssh -p 12345 user@127.0.0.1)

# home box (server role)
  tunnel server ready — forwarding incoming QUIC streams to 127.0.0.1:22
```

(If the fingerprints match what the other side printed, you've also done an
out-of-band certificate comparison — see [Security model](#security-model).)

### Step 5 — use it like a LAN

```sh
# on the laptop
ssh -p 12345 user@127.0.0.1
```

You're now in a shell on the home box. Every new local connection to
`127.0.0.1:12345` gets its own tunnel stream, so a second `ssh -p 12345`
window works concurrently.

### Step 6 — tear down

`Ctrl-C` / `q` / `Esc` on either side; both processes exit. The tunnel is
gone; next session, repeat from step 3 (addresses change every run).

If the tunnel drops on its own (NAT timeout, network flap, or a restart on
one side), the supervisor re-negotiates automatically — you don't repeat
steps — and only a terminal condition (e.g. setup errors) exits non-zero.

---

## Telegram address exchange (the default)

When a usable `[telegram]` table is configured — a token, a peer bot id and a
shared secret — both machines exchange addresses automatically using
Telegram's [bot-to-bot](https://core.telegram.org/api/bots/bot-to-bot)
capability. Each side's bot DMs the other side's bot:

- `PTUN READY <secret>` at startup (before STUN) — proves the peer bot is up
- `PTUN ROLE <client|server>` — declares the role, cross-checked by the peer
- `PTUN v1 <ip:port>` — the public address, sent after STUN

This is **the default**, not an opt-in. The manual prompt remains the fallback
whenever Telegram is unusable — no `[telegram]` table, an incomplete one, a
bad token, a peer bot that isn't answering, or a timeout. `--manual` (alias
`--no-telegram`) forces the manual prompt; `--telegram` validates and errors
early on a missing table.

### Set it up

1. Create **two** bots in [@BotFather](https://t.me/BotFather) (one per
   machine) and note each one's **API token** (`123456:ABC-DEF…`).
2. On **each** bot: BotFather → *Bot Settings* → *Bot-to-Bot Communication*
   → **Enable**. Without this, `sendMessage` to a bot returns
   `USER_BOT_TO_BOT_DISABLED`.
3. Get each bot's **numeric id** (BotFather can show it, or any `@id` bot on
   the bot's profile).
4. In each machine's `config.toml`, add a `[telegram]` table with **this
   machine's** token, the **peer bot's** id, and a shared secret both
   operators must agree on:

   ```toml
   [telegram]
   token = "123456:ABC-DEF…"   # THIS machine's bot token
   peer_bot_id = 987654321      # the PEER bot's numeric id
   secret = "shared-secret"      # must match the peer's config
   # timeout_secs = 120        # optional; default 120
   ```

   The two tables point at each other: machine A's `peer_bot_id` is bot B's
   id, and machine B's `peer_bot_id` is bot A's id. The `secret` goes in both
   configs unchanged — it travels to the peer in the `PTUN READY` line and is
   how each side proves the peer is up and means the same thing.
5. Run both sides:

   ```sh
   ./p2p-tunnel
   ```

   The exchange happens automatically — no flag needed. Each side announces
   its address and waits (up to `timeout_secs`) for the peer's. On success it
   proceeds straight to hole punching; on timeout or error it logs the
   reason and drops back to the manual prompt.

### How it stays loop-safe and stale-safe

Bots replying to bots can ping-pong forever, and `getUpdates` replays whatever
is already queued. This implementation prevents both:

- It **only ever sends its own address** and never auto-replies to incoming
  `PTUN` messages. It re-announces each time it (re-)enters Telegram mode, so
  a peer that started *after* the first send still sees it.
- It **ignores its own echoes** (messages whose `from.id` is its own bot
  id), so the reply it receives isn't treated as a new peer.
- It only accepts a `PTUN v1` payload from the **specific peer bot id**
  configured; messages from any other sender are discarded.
- It **rejects stale announcements by message date.** A `PTUN` line left over
  from a previous run would otherwise be accepted as a peer address whose NAT
  mapping is long gone. The client tracks the highest `update_id` it has
  consumed (via the `offset` parameter, so nothing is reprocessed) and only
  accepts peer lines whose Telegram `date` is younger than 10 minutes —
  anything older is ignored, and a *fresh* announcement from a peer that
  started before us is still accepted.

The payload format is `PTUN v1 <ip:port>`; anything not matching that prefix
is ignored. **Roles are not negotiated over Telegram** — you pick yours at
setup, and the peer's `PTUN ROLE` line is cross-checked against it. A conflict
(both sides picked the same role, which can never tunnel) is fatal at startup:
the app refuses to proceed rather than burn a punch cycle and fail silently.
Telegram only carries liveness, the role declaration, and the address.

## Configuration reference (`config.toml`)

The file is optional to *find* (`--config` selects it, default `./config.toml`)
but required to *exist*. Note that **unknown keys are silently ignored** —
typing a key name wrong won't error out, so copy the shipped sample.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `stun_servers` | `["host:port", …]` | *(required, non-empty)* | STUN servers tried in order (hostnames OK, port defaults to 19302 if omitted). Each gets up to 3 s; the whole list is tried twice. |
| `role` | `"client"` \| `"server"` | unset | **This machine's role** (v2). Optional: the `--role` flag wins over this key; when both are absent, the role is selected at the setup screen. The two sides must pick opposite roles — a conflict is fatal at startup. |
| `punch_interval_ms` | `u64` | `500` | Milliseconds between outbound hole-punch packets. |
| `punch_timeout_secs` | `u64` | `30` | Give up on hole punching after this long (the error includes how many packets were sent). |
| `keep_alive_interval_secs` | `u64` | `5` | Seconds between QUIC keep-alive PING packets sent while the tunnel is idle. Idle NAT devices drop the port mapping of a silent connection, so these small PINGs keep the tunnel alive; `0` disables keep-alive (the tunnel then dies after the NAT's idle timeout, typically a few minutes). |
| `local_tcp_listen_port` | `u16` | unset | **Read only if this machine is the client.** The `127.0.0.1` port that offers the tunnel (e.g. `12345`). Loopback only — never exposed to your LAN. |
| `remote_target_addr` | `"ip:port"` | unset | **Read only if this machine is the server.** The private TCP target on *this* machine's network that tunneled traffic is delivered to (e.g. `"127.0.0.1:22"`). |
| `[telegram].token` | `string` | unset | **This machine's bot API token.** Present in any usable `[telegram]` table; without it the exchange falls back to manual. |
| `[telegram].peer_bot_id` | `i64` | unset | The **peer bot's** numeric id — the `chat_id` its `PTUN` messages are sent to. |
| `[telegram].secret` | `string` | unset | The shared secret for the readiness handshake (`PTUN READY`). Both sides must use the same value; without it the table is treated as unusable and the exchange falls back to manual. |
| `[telegram].timeout_secs` | `u64` | `120` | How long to wait for the peer bot's address before falling back to the manual prompt. |

The shipped sample `config.toml` (in the repo root) has the `role` key,
both side keys, and the `[telegram]` table commented out with instructions;
copy it and edit.

## CLI reference

```
p2p-tunnel [OPTIONS]

Options:
      --config <CONFIG>   Path to the TOML config file [default: ./config.toml]
      --role <ROLE>       This machine's role: client | server
                         (wins over the `role` config key; if neither is
                         set, you get the setup-screen picker)
      --telegram          Force Telegram address exchange (requires a usable
                         `[telegram]` table; errors early otherwise). This is
                         the default when a usable table is configured.
      --manual            Force the manual "type the peer address" prompt
                         (alias: --no-telegram) — opts out of the default
      --tui               Show the live terminal UI (auto-enabled on a TTY)
      --no-tui            Force the plain log output, even on a TTY
      --verbose           Enable debug logging (RUST_LOG takes precedence if set)
  -h, --help              Print help
  -V, --version           Print version
```

**Live TUI.** When stdout is a real terminal the app runs a full-screen UI
(ratatui + crossterm) that visualizes the whole lifecycle:

```
┌ p2p-tunnel ──────────────────────────────────────────────────────────┐
┌ lifecycle ───────────────────────────────────────────────────────────┐
│ ✓ STUN ── ⠹ EXCHANGE ── · PUNCH ── · ROLE ── · QUIC ── · TUNNEL      │
└──────────────────────────────────────────────────────────────────────┘
┌ connection ──────────────────────────────────────────────────────────┐
│  you   185.235.254.56:33710                                          │
│  peer  141.98.10.63:62771                                           │
│  role  client      cert  9a4f1c2e…b7d0                                │
└──────────────────────────────────────────────────────────────────────┘
┌ events ──────────────────────────────────────────────────────────────┐
│ own public address: 185.235.254.56:33710                            │
│ peer address: 141.98.10.63:62771                                    │
│ role: client                                                        │
└──────────────────────────────────────────────────────────────────────┘
 working on: EXCHANGE — waiting for peer    q to abort
```

The stepper fills in as each phase completes (✓ done, animated spinner
active, · pending, ✗ error), the connection panel shows both public
addresses, the chosen role, the exchange mode, the configured port/target,
and the fresh cert fingerprint, and the events panel is a scrolling log.
The header turns green on `CONNECTED` and red on error (which also fills
the events panel). Press **`q`** or **Esc** to abort; when a `[telegram]`
table is configured, **`t`** toggles between Telegram and manual address
exchange at any time (the status line shows the current mode). It's
auto-enabled only when stdout is a TTY — when piped or redirected the
original plain logging is used, and `--no-tui` forces that path while
`--tui` forces the UI (handy for testing). When the TUI is active, `tracing`
logging is silenced so the stderr formatter never interleaves with the
alternate screen; the TUI is the single source of truth. `RUST_LOG` is
ignored in that case (the TUI is the output).

The startup setup screen (role + setting + channel) runs first: pick the
role, fill the setting, and hit Enter to validate. Fatal errors and a
role conflict both re-open the screen — the operator always lands on a
valid, mutually-consistent selection before the run proceeds.

Logging levels (non-TUI path): `info` by default (the lines shown in the
quick start), `--verbose` or `RUST_LOG=debug` for per-packet/per-round
detail (every punch packet sent, every ignored non-peer packet, STUN round
timing, …).

On success the process exits 0 when the tunnel ends; on failure it prints
`error: <details>` plus an actionable `hint:` line to stderr and exits 1.

---

## Examples

### SSH to a home server (the canonical use case)

As in the [quick start](#quick-start): laptop's `config.toml` has the
`client` role and `local_tcp_listen_port = 12345`, the home box has the
`server` role and `remote_target_addr = "127.0.0.1:22"`, then on the laptop:

```sh
ssh -p 12345 user@127.0.0.1
```

Works with any SSH option: `scp -P 12345 user@127.0.0.1:/path/file .`,
`ssh -p 12345 -L 8080:localhost:8080 user@127.0.0.1`, etc.

### `nc` / any plain TCP service

Expose a private HTTP server, a game port, a database, anything:

```toml
# server role — exposes the service
remote_target_addr = "192.168.1.20:8080"
```

```sh
# client role, local_tcp_listen_port = 18080
curl http://127.0.0.1:18080/
nc 127.0.0.1 18080
```

### Several simultaneous connections

Each local TCP connection to the client's port maps to its own QUIC stream
and its own target connection on the server side — no sharing, no
interleaving. Open as many `ssh -p 12345 user@127.0.0.1` sessions as you
like; each is independent, and one closing doesn't affect the others (the
tunnel itself stays up until the QUIC connection drops).

### Reaching the tunnel from another device (phone, tablet)

The client-side listener binds `127.0.0.1` only — deliberately, so nothing
else on your LAN can touch the tunnel port. From another device, hop through
the laptop with a standard SSH local-forward:

```sh
# on the phone (or any device that can reach the laptop over the LAN)
ssh -L 12345:127.0.0.1:12345 me@laptop.local
# then connect to 127.0.0.1:12345 on the phone
```

### Piping without a full session

Half-close is respected, so one-shot transfers behave — data goes in, output
comes back, and the connection closes cleanly with EOF:

```sh
# one-shot command; stdout comes back over the tunnel
ssh -p 12345 user@127.0.0.1 'uptime'

# stream a file through the tunnel to a remote command
cat file.txt | ssh -p 12345 user@127.0.0.1 'tar xzf - -C /tmp'
```

---

## Security model

Read this before using it anywhere sensitive.

- **Transport encryption is real.** QUIC mandates TLS 1.3: the channel is
  confidential and integrity-protected, and the handshake's cryptographic
  signatures *are* still verified — the permissive part is purely the *trust*
  decision (any certificate is accepted), not the math.
- **Identity is *not* verified.** The client accepts *any* server
  certificate — no chain validation, no hostname check. An attacker on a
  path where they can intercept your UDP flow could in principle terminate
  and re-wrap it. This is an explicit PoC trade-off, not an oversight.
- **Mitigation: fingerprint comparison.** Both sides log the SHA-256
  fingerprint of the certificate in use at session start (the line shown in
  the quick start). Compare them out-of-band — the same way you'd compare an SSH
  host key — and a MITM is detected.
- **The local listener is loopback-only** (`127.0.0.1`), so devices on your
  LAN can't reach the tunnel port directly.
- **Secrets travel only in the exchange path** — the shared secret used in the
  readiness handshake is a config value, and only the two bot-to-bot channels
  see it; the public address travels as a `PTUN v1` line whose payload is
  just `ip:port`. The rest of the exchange carries no keys.
- **Planned hardening:** certificate fingerprint pinning (a shared
  out-of-band secret checked automatically). Until that lands, treat this as
  a tunnel between two *known, mutually trusted* peers — like an ad-hoc SSH
  setup with `StrictHostKeyChecking=accept-new`.

## Troubleshooting

| Symptom | Likely cause | What to do |
|---------|--------------|------------|
| `STUN discovery failed` | No internet, outbound UDP blocked, or **CGNAT** (carrier-grade NAT — the "public" address the carrier assigns can't receive inbound traffic) | Check connectivity / firewall. If you're on a mobile hotspot or CGNAT, this MVP can't traverse that (TURN fallback is planned). Try the other network. |
| `hole punching timed out after …s (sent N punch packets)` | Stale peer address (their NAT binding expired or their process restarted), or one side behind a **symmetric NAT** | Re-run *both* sides and exchange fresh addresses within the same session. If one side is on a mobile hotspot, expect failure (symmetric NAT). |
| Punch succeeds, then `QUIC handshake` error | Middlebox interference, or the peer process exited mid-handshake | Retry on both sides. If persistent, a middlebox may be mangling the flow. |
| `… is required for the … role` error at startup | Your config is missing the key for the role you picked | Add `remote_target_addr` (server role) or `local_tcp_listen_port` (client role) — easiest: set **both** in every config, per the [tip](#which-side-exposes-the-service). |
| `role misconfiguration: …` at startup | Both sides picked the same role (e.g. both `client`) — a tunnel can never work | Fix one side's role (`--role` or the `role` key) and re-run; the setup screen reopens with the conflict shown. |
| Tunnel up, but the target connection dies instantly (client sees EOF) | `remote_target_addr` isn't reachable from the server machine | Test locally on the server machine (`nc 127.0.0.1 22`); fix the target, then re-run. The server logs a `cannot reach target; closing stream` warning. |
| `bind local TCP listener … (is the port already in use?)` | The local port is taken by another process (or a zombie previous run) | Pick another `local_tcp_listen_port`, or kill the old process. |
| It worked once and never again | NAT bindings / public addresses are ephemeral; some NATs age out mappings quickly | The supervisor retries automatically — the tunnel re-negotiates on its own. If it never recovers, stale config or a dead peer is the likely cause: fix that, then re-run. |

General debug moves:

- `--verbose` (or `RUST_LOG=debug`) on **both** sides: you'll see each punch
  packet, each STUN round, and exactly where things stop.
- `RUST_LOG=trace` on one side for maximum noise.
- Confirm the **role lines** point the tunnel the direction you expect (see
  [Which side exposes the service](#which-side-exposes-the-service)).

## Limitations

- **IPv4 only** for the punched socket (`0.0.0.0` bind). IPv6 would need no
  punching at all — it's a future item.
- **One tunnel per run.** The supervisor re-negotiates automatically, but the
  process itself is single-flight: it runs one tunnel at a time, and there is
  no persistent signaling channel across restarts — each session re-exchanges
  addresses. Multiplexing refinements are future work.
- **No persistent signaling.** Addresses are session-scoped; after a process
  restart, re-run both sides (the supervisor handles in-process drops, not
  fresh pairings).
- **Simultaneous hole punching works best against *cone* NATs.** Symmetric
  NATs / CGNAT (common on mobile hotspots) will typically fail the punch
  within the timeout — a TURN relay fallback is on the roadmap.
- **One listen port and one target per side** (though concurrent
  *connections* through them are fully supported).
- **MVP trust model** (accept-any cert) — see [Security model](#security-model).

## Development

```sh
cargo build                # compile
cargo test                 # ~109 tests (105 unit + 4 integration)
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
cargo run -- --verbose     # run with debug logging
```

**Tests** cover STUN encode/parse (incl. edge cases: unknown attrs, wrong
transaction IDs, v4/v6), punch timing/filtering/timeout, role validity and
cross-check symmetry, cert/fingerprint construction, the bridge's copy +
half-close semantics (via in-memory `tokio::io` streams), setup validation
(role flag precedence, setting validation, exchange-mode resolution), and
the supervisor's retry/backoff decisions, and — as integration tests — the
full Telegram exchange against a local mock Bot API (`tests/telegram/mock_bot_api.py`,
including stale-backlog rejection and the READY/ROLE handshake) plus TUI
prompt round-trips through the event channel. By project decision there is
deliberately **no loopback test of the QUIC server+client path** (one machine
playing both roles is ambiguous); the real handshake is validated in
two-machine tests.

**CI** (`.github/workflows/ci.yml`) runs on every push/PR: lint (fmt + clippy
`-D warnings`), release build + tests on a Linux/macOS/Windows matrix, and a
static `x86_64-unknown-linux-musl` binary artifact.

**Phase 12** (real-world NAT validation) is in progress; `tests/nat-sim/`
contains helpers for a local two-NAT simulation (network namespaces +
iptables): a fake STUN server that *is* the NAT, a TCP echo target, and a
probe client.

### Repository layout

```
.
├── .github/workflows/
│   ├── ci.yml                 # CI: lint + build/test on Linux/macOS/Windows + static musl binary
│   └── release.yml            # tag → prebuilt binaries published as a GitHub Release
├── Cargo.toml / Cargo.lock
├── config.toml                # sample configuration
├── PROGRESS.md                # implementation scratchpad — phase-by-phase state
├── README.md                  # this file
├── tests/
│   ├── telegram_exchange.rs   # integration test: full exchange vs. mock Bot API
│   ├── tui_prompt.rs          # integration test: TUI prompt channel round-trip
│   ├── telegram/mock_bot_api.py  # mock Telegram Bot API server for the exchange test
│   └── nat-sim/               # Phase 12 helpers: fake STUN/NAT, echo target, probe client
└── src/
    ├── main.rs                # boot, wiring, error hints
    ├── supervisor.rs          # reconnect supervisor: one attempt = exchange → STUN → cross-check → punch → QUIC → tunnel
    ├── setup.rs               # startup setup: role/setting/channel resolution + validation
    ├── config.rs              # Config::load (serde/toml)
    ├── cli.rs                 # clap CLI + peer-address prompt/parsing
    ├── stun.rs                # manual RFC 5389 client (encode/parse/discover)
    ├── punch.rs               # hole punching loop
    ├── role.rs                # role validity + cross-check symmetry
    ├── quic.rs                # certs, verifier, endpoint, connect/accept
    ├── tunnel.rs              # TCP↔QUIC bridges (client + server sides)
    ├── telegram.rs            # Telegram bot-to-bot signaling (READY + ROLE + address)
    ├── tui.rs                 # ratatui/crossterm render loop, setup screen, inline prompt editor
    └── tui_state.rs           # TUI state (phases, logs, setup form) shared via an event channel
```

`tests/` is the cargo integration-test directory; `tests/nat-sim/` and
`tests/telegram/` hold Python helpers used by the `.rs` tests there.

The full development plan lives in `plan.md` (repo parent directory);
`PROGRESS.md` tracks what is done and what the next phase needs.

## License

MIT — see `LICENSE`.
