# p2p-tunnel (Python)

> **Status: under development** on the `python` branch. This branch is a
> ground-up rewrite of the Rust `p2p-tunnel` (on `main`) in Python — same
> wire behavior, with a few **v2 orchestration upgrades** (you select the
> role at startup, Telegram is the default channel, and the app reconnects
> on its own).
>
> - **[PLAN.md](PLAN.md)** — the full plan, including the v2 divergences
>   from the Rust reference (marked D1–D6)
> - **[PROGRESS.md](PROGRESS.md)** — phase-by-phase development log
>
> | Phase | What | Status |
> |---|---|---|
> | 0–1 | scaffold, `config.toml`, CLI + prompt loop | done |
> | 2 | STUN (RFC 5389, hand-rolled) | done |
> | 3 | simultaneous UDP hole punching | done |
> | 4–5 | certs + QUIC endpoint on the reused socket | done |
> | 6–7 | TCP↔QUIC bridge (client / server) | in progress |
> | 8 | Telegram signaling — the *default* channel | pending |
> | 9 | role model + startup setup + CLI v2 | pending |
> | 10 | full pipeline wiring | pending |
> | 11 | reconnect supervisor (auto re-negotiation) | pending |
> | 12 | live TUI (curses; Windows via optional extra) | pending |
> | 13 | logging polish (parity with the Rust log) | pending |
> | 14–15 | loopback e2e + real-NAT verification | pending |
> | 16 | docs, CI, cleanup, `v0.1.0-py` tag | pending |

A small Python CLI that lets two machines behind NATs reach each other's
**private TCP services** — no ports to open, no relay server, no account.

Select which machine exposes the service, type (or let the bots exchange)
one address into the other, and a normal TCP tool (`ssh`, `nc`, `curl`, …)
works as if the two machines were on the same LAN.

- **STUN** (RFC 5389, hand-rolled) discovers each machine's public `ip:port`
- **Simultaneous UDP hole punching** opens the NAT hole
- **QUIC / TLS 1.3** (`aioquic` — the *only* third-party dependency) carries
  an encrypted, reliable byte pipe over the hole
- A **TCP↔QUIC stream bridge** turns the pipe into ordinary TCP connections
- **You pick the role at startup** (client = "give me a local port",
  server = "expose this service"), and the two sides cross-check it over
  Telegram — a misconfigured pair is reported, not silently reversed
- **Telegram bot-to-bot is the default** address channel (manual prompt is
  the fallback), with **automatic re-negotiation** whenever the tunnel
  drops
- A **live TUI** (curses on Linux/macOS, `windows-curses` extra on Windows)
  visualizes the whole lifecycle — setup screen, phase stepper, connection
  diagram, scrolling event log — and auto-enables on any real terminal

```
┌────────────────────────┐                         ┌────────────────────────┐
│  Machine A (laptop)    │                         │  Machine B (home box)  │
│                        │  STUN servers (UDP)     │                        │
│  app ──TCP──► 127.0.0.1│◄────────────────────────│  127.0.0.1:22 ── sshd  │
│          :12345        │                         │                        │
│   (client role —       │                         │   (server role —       │
│    you selected it)    │                         │    you selected it)    │
│  ┌───────────────────┐ │                         │ ┌───────────────────┐  │
│  │  QUIC (aioquic)   │ │════ punched UDP hole ═══│ │  QUIC (aioquic)   │  │
│  └─────────▲─────────┘ │                         │ └─────────▲─────────┘  │
│            │           │                         │           │            │
│  ┌─────────┴─────────┐ │   1. setup + role       │  ┌─────────┴─────────┐ │
│  │  ONE UDP socket   │ │   2. Telegram handshake │  │  ONE UDP socket   │ │
│  │  STUN→punch→QUIC  │ │   3. STUN + exchange    │  │  STUN→punch→QUIC  │ │
│  └───────────────────┘ │   4. punch → QUIC → TCP │  └───────────────────┘ │
└────────────────────────┘                         └────────────────────────┘
```

**The killer detail:** each side creates **one UDP socket up front and reuses
it for the entire session** — STUN discovery, hole punching, and finally the
QUIC endpoint (`aioquic` takes ownership of it via
`loop.create_datagram_endpoint(sock=…)`). Creating a new socket would get a
new NAT mapping and close the freshly-punched hole, so this reuse is what
makes the design work.

---

## Table of contents

1. [How it works](#how-it-works)
2. [The one rule: you pick who exposes the service](#the-one-rule-you-pick-who-exposes-the-service)
3. [Requirements](#requirements)
4. [Installing](#installing)
5. [Quick start (two machines, SSH to a home server)](#quick-start)
6. [Automatic address exchange over Telegram (the default)](#automatic-address-exchange-over-telegram-the-default)
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

Everything below happens on **both** machines, in the same order:

### 1. Setup: role + settings (you decide)

At startup the app asks (TUI setup screen, or plain prompts):

- **role** — `client` or `server`
- **client** → the local TCP port to offer (bound to `127.0.0.1` only)
- **server** → the private service to expose, `ip:port`
- **channel** — Telegram (default when configured) or manual

Both values are prefilled from `config.toml` and editable. This replaces
the Rust tool's address-derived role: explicit intent beats a derived
guess, and you always know which way traffic flows before you start.

### 2. STUN discovery

A raw RFC 5389 **Binding Request** is sent from THE socket to each configured
STUN server (manual implementation — stdlib `socket` only, no STUN
library, because the socket must stay under our control for the later
phases). Each server gets up to 3 s, and the whole list is tried twice. The
response's `XOR-MAPPED-ADDRESS` attribute tells us the public `ip:port` the
rest of the internet sees for this socket.

### 3. Telegram handshake + role cross-check (default channel)

When a `[telegram]` table is configured, the two bots DM each other:
`PTUN READY <secret>`, then a new optional `PTUN ROLE <client|server>` line
(PTUN protocol v1.1; older Rust peers ignore it — they only match the
`PTUN READY `/`PTUN v1 ` prefixes — and a Python peer talking to a Rust peer
falls back to the legacy IP-derived role with a warning).

If both sides declared the **same** role, the TUI says
`role misconfiguration: both sides selected 'server'` and returns to the
setup screen instead of silently building a tunnel that can't work.

### 4. Peer address exchange

Your public address is printed. Two ways to complete the exchange:

- **Telegram (default when configured):** the two bots DM each other their
  public addresses — no copy/paste. Any failure (token, timeout, peer bot
  down) drops straight back to the manual prompt.
- **Manual (fallback, or forced with `--manual`):** share your address with
  the other person (chat, phone, carrier pigeon) and type *their* address
  into the prompt. Input is validated and re-prompted on bad input.

> **Addresses are session-scoped.** The port (and sometimes the IP) changes
> every time the process runs, and the NAT mapping goes away when the
> process exits or the binding expires. There is no persistent "tunnel
> address" — exchange a fresh address for every session (or let the bots
> do it on every re-negotiation).

### 5. UDP hole punching

Both sides repeatedly send a small UDP packet (a random 8-byte session
nonce) to the peer's public address, every `punch_interval_ms`
(default 500 ms). The moment a packet **from the peer's exact address**
arrives, the punch has succeeded on that side; anything from other senders
is ignored. Packets are sent for up to `punch_timeout_secs` (default 30 s).
Because both sides punch at the same time, typical cone NATs open within a
few seconds of both processes starting.

### 6. Self-signed certificate + QUIC handshake

A fresh **ECDSA P-256 self-signed certificate** (CN `p2p-tunnel`) is
generated in memory (`cryptography`). The server presents it; the client
accepts *any* certificate — see the [security model](#security-model) for
what that means in practice. **Both sides log the certificate's SHA-256
fingerprint** so the two humans can compare it out-of-band, exactly like an
SSH host-key fingerprint.

The punched UDP socket is then handed to `aioquic`, which takes ownership
and performs the TLS 1.3 / QUIC handshake over it. Your selected role
decides the side: **server accepts, client connects**.

### 7. TCP↔QUIC stream bridge + keep-alive

- **Client role:** a local TCP listener on `127.0.0.1:<local_tcp_listen_port>`
  accepts connections. Each accepted connection gets its **own bidirectional
  QUIC stream**, so several concurrent connections (multiple `ssh` sessions)
  are independent.
- **Server role:** each incoming QUIC stream gets its **own TCP connection**
  to the service you selected at setup.

Bytes are copied in both directions with **half-close semantics**: EOF in
one direction shuts down only that direction — the other keeps flowing
until it sees its own EOF. (This is what makes patterns like
`echo x | ssh host cat` work instead of dying.) If the server's target is
unreachable, the client sees a clean EOF rather than hanging.

QUIC keep-alive PINGs (default every 5 s) keep the NAT mappings alive
while the tunnel is idle.

### 8. Reconnect supervisor

A *stream-level* failure (one local client disconnects; the exposed
service is briefly down) is **not** a tunnel loss — the tunnel keeps
serving the other streams. Any *tunnel-level* loss (QUIC connection
dropped, NAT path changed, peer restarted) triggers a **full
re-negotiation** — Telegram handshake, fresh address exchange, punch,
handshake — with exponential backoff (2 s → 30 s cap, reset after 30 s of
stability). The Telegram channel stays open for the whole app lifetime.
Unlimited attempts until you press `q` / Ctrl-C.

---

## The one rule: you pick who exposes the service

The Rust tool derived the role from the two public addresses (lower IP =
server), which forced a "which machine has the lower IP?" puzzle. Here:

> **You select the role at startup.** `server` means "I expose a private
> service — traffic coming through the tunnel lands on
> `remote_target_addr` on **my** machine." `client` means "I want a local
> port — `ssh -p <port> user@127.0.0.1` on **my** machine reaches the
> peer's service."

Consequences:

- To reach a service on your home box from a laptop: the **home box runs
  as `server`** (exposing, say, `127.0.0.1:22`), the **laptop runs as
  `client`** (offering, say, port `12345`). No IP arithmetic, no
  "reconfigure to match the direction" dance.
- If you select the same role on both machines, the Telegram cross-check
  catches it (`role misconfiguration: both sides selected 'server'`) and
  sends you back to setup. In manual mode (or against a Rust peer that
  can't send its role) the mismatch surfaces as repeated QUIC handshake
  failures, with a hint telling you to pick opposite roles.

**Tip:** put *both* keys in *every* machine's config —
`local_tcp_listen_port` and `remote_target_addr`. Setup prefills from them
and lets you edit, so switching roles later is a keystroke, not a config
hunt.

---

## Requirements

- **Python ≥ 3.11** (3.11–3.14 supported; the port uses `tomllib`,
  modern `asyncio`, and stdlib `ssl`)
- **One third-party package:** `aioquic` (pure-Python QUIC + TLS 1.3),
  which pulls `cryptography` (the TLS crypto) transitively. Everything else
  — STUN, punching, Telegram HTTP, TUI, config, tests — is the standard
  library
- **Outbound UDP** to a STUN server (default config uses Google/Cloudflare)
  and to the peer's public address
- **Two machines whose NATs are not symmetric** (see
  [Limitations](#limitations))
- For real use: a way to compare the two fingerprints out-of-band (any
  chat); for the default exchange mode, two Telegram bots (see
  [Telegram](#automatic-address-exchange-over-telegram-the-default))

## Installing

```sh
python3 -m venv .venv
.venv/bin/pip install p2p-tunnel        # or: pip install -e . from a checkout
.venv/bin/p2p-tunnel --help
```

That's the whole dependency story: `pip install p2p-tunnel` fetches
`aioquic` + `cryptography` (+ their small transitive set) and nothing
else.

**Windows note:** stock Windows CPython ships without `curses`, so the
live TUI needs the optional extra:

```sh
pip install "p2p-tunnel[tui]"           # adds windows-curses on Windows
```

On Linux/macOS the stdlib `curses` is used. If no curses is available at
all, the app falls back to plain log output automatically (with a hint).

---

## Quick start

Goal: from a laptop (behind any NAT), `ssh` into your home server's private
SSH — no router config, no public IP requirement, no relay.

### Step 1 — install on both machines

`pip install p2p-tunnel` (or `pip install -e .` from a checkout).

### Step 2 — write the config on both machines

**Home box** (`config.toml`):

```toml
stun_servers = [
    "stun.l.google.com:19302",
    "stun.cloudflare.com:3478",
]

# The private service on THIS box to expose. You'll run this machine as
# the SERVER role. Here: SSH on loopback.
remote_target_addr = "127.0.0.1:22"
```

**Laptop** (`config.toml`):

```toml
stun_servers = [
    "stun.l.google.com:19302",
    "stun.cloudflare.com:3478",
]

# The port the laptop will offer: ssh -p 12345 user@127.0.0.1
# You'll run this machine as the CLIENT role.
local_tcp_listen_port = 12345
```

(See [Configuration reference](#configuration-reference-configtoml) for
every key. Setup prefills from these and lets you edit, so the config can
also just carry both keys on every machine.)

### Step 3 — run on both machines

```sh
# home box
p2p-tunnel
# laptop
p2p-tunnel
```

At the setup screen, select **server** on the home box (service:
`127.0.0.1:22`) and **client** on the laptop (port: `12345`). Without a
`[telegram]` table the channel is manual: each side prints its public
address, and you type each one into the other's prompt:

```text
# home box                                       # laptop
role: server    service: 127.0.0.1:22            role: client    local port: 12345
channel: manual                                   channel: manual
Your public address is: 93.184.216.34:51000       Your public address is: 203.0.113.7:48000
Give it to the other party, then enter            Give it to the other party, then enter
their public address below.                       their public address below.
Enter peer's public address (ip:port):            Enter peer's public address (ip:port):
203.0.113.7:48000                                 93.184.216.34:51000
```

### Step 4 — watch both sides connect

Within seconds (usually well under the 30 s punch timeout) both sides log
success:

```text
# home box (server role)
  hole punched: packet received from peer  elapsed_ms=1412  sent=3
  role = server
  generated self-signed certificate …  fingerprint=9f2c…ab
  QUIC endpoint ready
  waiting for the peer's QUIC connection…
  QUIC connection accepted
  tunnel server ready — forwarding incoming QUIC streams to 127.0.0.1:22

# laptop (client role)
  hole punched: packet received from peer  elapsed_ms=1873  sent=4
  role = client
  generated self-signed certificate …  fingerprint=9f2c…ab   ← compare with home box
  QUIC endpoint ready
  QUIC connection established
  tunnel client listening — connect to 127.0.0.1:12345 (e.g. ssh -p 12345 user@127.0.0.1)
```

(If the fingerprints match what the other side printed, you've also done an
out-of-band certificate comparison — see [Security model](#security-model).)

If the tunnel later drops (network change, sleep/wake, NAT rebinding), the
app re-negotiates on its own and logs `re-negotiating (attempt 2)` — no
re-run needed.

### Step 5 — use it like a LAN

```sh
# on the laptop
ssh -p 12345 user@127.0.0.1
```

You're now in a shell on the home box. Every new local connection to
`127.0.0.1:12345` gets its own tunnel stream, so a second `ssh -p 12345`
window works concurrently.

### Step 6 — tear down

`Ctrl-C` on either side; both processes exit. The tunnel is gone; next
session, repeat from step 3 (addresses change every run).

---

## Automatic address exchange over Telegram (the default)

The manual "type the address" prompt always works — it's the fallback. But
if you add a `[telegram]` table, **Telegram becomes the default channel**:
both machines' bots DM each other their public addresses (and their
selected roles) automatically, on every (re-)negotiation. No copy/paste,
not even the first time.

Use `--manual` to force the manual prompt even when a `[telegram]` table
exists; any Telegram failure (bad token, API error, wait timeout, peer bot
down) drops back to the manual prompt for that attempt automatically —
Telegram is a convenience, never a hard dependency.

### Set it up

1. Create **two** bots in [@BotFather](https://t.me/BotFather) (one per
   machine) and note each one's **API token** (`123456:ABC-DEF…`).
2. On **each** bot: BotFather → *Bot Settings* → *Bot-to-Bot Communication*
   → **Enable**. Without this, `sendMessage` to a bot returns
   `USER_BOT_TO_BOT_DISABLED`.
3. Get each bot's **numeric id** (BotFather can show it, or any `@id` bot
   on the bot's profile).
4. In each machine's `config.toml`, add a `[telegram]` table with **this
   machine's** token and the **peer bot's** id:

   ```toml
   [telegram]
   token = "123456:ABC-DEF…"   # THIS machine's bot token
   peer_bot_id = 987654321      # the PEER bot's numeric id
   # timeout_secs = 120         # optional; default 120
   ```

   The two tables point at each other: machine A's `peer_bot_id` is bot B's
   id, and machine B's `peer_bot_id` is bot A's id.

### The on-the-wire protocol (PTUN v1.1)

Each (re-)negotiation, each bot sends its peer:

```
PTUN READY <secret>            # "I'm here, this session, this is my secret"
PTUN ROLE client|server        # new in v1.1; the role you selected at setup
PTUN v1 <ip:port>              # your public address, after STUN
```

The peer accepts a line only if it's from the **configured peer bot id**,
fresh (younger than 10 minutes — stale lines from an old run are ignored),
and new since the last attempt (the `getUpdates` offset cursor guarantees
each attempt only ever sees *new* messages). Anything not matching the
`PTUN ` prefix is ignored.

**Interop:** Rust `main`-branch peers speak v1 (no `PTUN ROLE` line). The
classifier only matches the `PTUN READY ` / `PTUN v1 ` prefixes, so Rust
peers ignore the ROLE line, and a Python peer with no ROLE line from the
peer falls back to the legacy IP-derived role (with a TUI warning if that
differs from what you selected).

### How it stays loop-safe and stale-safe

Bots replying to bots can ping-pong forever, and `getUpdates` replays
whatever is already queued. The implementation prevents both:

- It **only ever sends its own lines** and never auto-replies to incoming
  `PTUN` messages. It re-announces on every (re-)negotiation, so a peer
  that started *after* the first send still sees it.
- It **ignores its own echoes** (messages whose `from.id` is its own bot
  id), so the reply it receives isn't treated as a new peer.
- It only accepts `PTUN` payloads from the **specific peer bot id**
  configured; messages from any other sender are discarded.
- It **rejects stale announcements by message date** and **tracks the
  highest consumed `update_id`** (via the `offset` parameter), so a drop
  and re-negotiation never re-reads the old address whose NAT mapping is
  long gone.
- The exchange is **idempotent and order-independent**: on a drop, both
  sides re-negotiate at slightly different times; each waits for the first
  *fresh* peer line of the type it needs, duplicates are ignored — the two
  attempts interleave without deadlock.

One `getUpdates` polling loop lives for the whole app lifetime; attempts
reuse it — there is no per-attempt re-connection to the Bot API.

## Configuration reference (`config.toml`)

The file is optional to *find* (`--config` selects it, default
`./config.toml`) but required to *exist*. Note that **unknown keys are
silently ignored** — typing a key name wrong won't error out, so copy the
shipped sample.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `stun_servers` | `["host:port", …]` | *(required, non-empty)* | STUN servers tried in order (hostnames OK, port defaults to 19302 if omitted). Each gets up to 3 s; the whole list is tried twice. |
| `punch_interval_ms` | `int` | `500` | Milliseconds between outbound hole-punch packets. |
| `punch_timeout_secs` | `int` | `30` | Give up on hole punching after this long (the error includes how many packets were sent). |
| `keep_alive_interval_secs` | `int` | `5` | Seconds between QUIC keep-alive PING packets sent while the tunnel is idle. Idle NAT devices drop the port mapping of a silent connection, so these small PINGs keep the tunnel alive; `0` disables keep-alive (the tunnel then dies after the NAT's idle timeout, typically a few minutes). |
| `local_tcp_listen_port` | `int` | unset | **Used when you select the client role.** The `127.0.0.1` port that offers the tunnel (e.g. `12345`). Loopback only — never exposed to your LAN. |
| `remote_target_addr` | `"ip:port"` | unset | **Used when you select the server role.** The private TCP target on *this* machine's network that tunneled traffic is delivered to (e.g. `"127.0.0.1:22"`). |
| `[telegram].token` | `string` | unset | This machine's bot API token. The whole `[telegram]` table is optional; when present (and working) Telegram is the default channel. |
| `[telegram].peer_bot_id` | `int` | unset | The **peer bot's** numeric id — the `chat_id` the `PTUN` messages are sent to. |
| `[telegram].timeout_secs` | `int` | `120` | How long to wait for the peer bot's lines before falling back to the manual prompt. |

The shipped sample `config.toml` (in the repo root) has both role keys and
the `[telegram]` table commented out with instructions; copy it and edit.

## CLI reference

```
p2p-tunnel [OPTIONS]

Options:
      --config <CONFIG>  Path to the TOML config file [default: ./config.toml]
      --telegram         Use Telegram exchange (the default when a [telegram]
                         table exists; passing it without one is an error)
      --manual           Force the manual prompt, even when Telegram is
                         configured (alias: --no-telegram)
      --tui              Show the live terminal UI (auto-enabled on a TTY)
      --no-tui           Force the plain log output, even on a TTY
      --verbose          Enable debug logging (LOG_LEVEL takes precedence if set)
  -h, --help             Print help
  -V, --version          Print version
```

> `--manual`/`--no-telegram` land in Phase 9 (CLI v2); until then
> `--telegram` is an opt-in flag as in the Rust tool.

**Live TUI.** When stdout is a real terminal the app runs a full-screen UI
(`curses` on Linux/macOS, the optional `windows-curses` extra on Windows)
that visualizes the whole lifecycle:

```
┌ p2p-tunnel ──────────────────────────────────────────────────────────┐
┌ lifecycle ───────────────────────────────────────────────────────────┐
│ ✓ SETUP ── ✓ TELEGRAM ── ✓ STUN ── ⠹ PUNCH ── · QUIC ── · TUNNEL     │
└──────────────────────────────────────────────────────────────────────┘
┌ connection ──────────────────────────────────────────────────────────┐
│  you   185.235.254.56:33710   role client    cert 9a4f1c2e…b7d0      │
│  peer  141.98.10.63:62771   role server   (confirmed via Telegram)   │
└──────────────────────────────────────────────────────────────────────┘
┌ events ──────────────────────────────────────────────────────────────┐
│ own public address: 185.235.254.56:33710                            │
│ peer address: 141.98.10.63:62771                                    │
└──────────────────────────────────────────────────────────────────────┘
 re-negotiating (attempt 2) — backoff 4s        q to quit
```

The stepper fills in as each phase completes (✓ done, animated spinner
active, · pending, ✗ error), the connection panel shows both public
addresses, the confirmed roles, and the fresh cert fingerprint, and the
events panel is a scrolling log. The header turns green on `CONNECTED` and
red on error; after a tunnel loss the status line shows
`re-negotiating (attempt N)` with the backoff countdown. Press **`q`** or
**Esc** to abort; when a `[telegram]` table is configured, **`t`** toggles
between Telegram and manual address exchange. It's auto-enabled only when
stdout is a TTY — when piped or redirected the original plain logging is
used, and `--no-tui` forces that path while `--tui` forces the UI (handy
for testing). When the TUI is active, console logging is silenced so the
stderr formatter never interleaves with the alternate screen; the TUI is
the single source of truth.

Logging levels (non-TUI path): `info` by default (the lines shown in the
quick start), `--verbose` or `LOG_LEVEL=debug` for per-packet/per-round
detail (every punch packet sent, every ignored non-peer packet, STUN round
timing, …).

On success the process exits 0 when the tunnel ends; on failure it prints
`error: <details>` plus an actionable `hint:` line to stderr and exits 1
(the supervisor keeps retrying on tunnel loss; `q`/Ctrl-C is the exit).

---

## Examples

### SSH to a home server (the canonical use case)

As in the [quick start](#quick-start): laptop selects **client** with
`local_tcp_listen_port = 12345`, home box selects **server** exposing
`remote_target_addr = "127.0.0.1:22"`, then on the laptop:

```sh
ssh -p 12345 user@127.0.0.1
```

Works with any SSH option: `scp -P 12345 user@127.0.0.1:/path/file .`,
`ssh -p 12345 -L 8080:localhost:8080 user@127.0.0.1`, etc.

### `nc` / any plain TCP service

Expose a private HTTP server, a game port, a database, anything:

```toml
# machine running as server
remote_target_addr = "192.168.1.20:8080"
```

```sh
# other machine running as client (local_tcp_listen_port = 18080)
curl http://127.0.0.1:18080/
nc 127.0.0.1 18080
```

### Several simultaneous connections

Each local TCP connection to the client's port maps to its own QUIC stream
and its own target connection on the server side — no sharing, no
interleaving. Open as many `ssh -p 12345 user@127.0.0.1` sessions as you
like; each is independent, and one closing doesn't affect the others (the
tunnel itself keeps running, and re-negotiates if it drops).

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

Half-close is respected, so one-shot transfers behave — data goes in,
output comes back, and the connection closes cleanly with EOF:

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
  signatures *are* still verified (by `cryptography`) — the permissive part
  is purely the *trust* decision (any certificate is accepted), not the
  math.
- **Identity is *not* verified.** The client accepts *any* server
  certificate — no chain validation, no hostname check. An attacker on a
  path where they can intercept your UDP flow could in principle terminate
  and re-wrap it. This is an explicit PoC trade-off, not an oversight.
- **Mitigation: fingerprint comparison.** Both sides log the SHA-256
  fingerprint of the certificate in use (the line shown in the quick
  start). Compare them out-of-band — the same way you'd compare an SSH
  host key — and a MITM is detected.
- **The local listener is loopback-only** (`127.0.0.1`), so devices on your
  LAN can't reach the tunnel port directly.
- **Planned hardening:** certificate fingerprint pinning (a shared
  out-of-band secret checked automatically). Until that lands, treat this
  as a tunnel between two *known, mutually trusted* peers — like an ad-hoc
  SSH setup with `StrictHostKeyChecking=accept-new`.

## Troubleshooting

| Symptom | Likely cause | What to do |
|---------|--------------|------------|
| `STUN discovery failed` | No internet, outbound UDP blocked, or **CGNAT** (carrier-grade NAT — the "public" address the carrier assigns can't receive inbound traffic) | Check connectivity / firewall. If you're on a mobile hotspot or CGNAT, this MVP can't traverse that (TURN fallback is planned). Try the other network. |
| `hole punching timed out after …s (sent N punch packets)` | Stale peer address (their NAT binding expired or their process restarted), or one side behind a **symmetric NAT** | With the supervisor + Telegram the app retries on its own and re-exchanges fresh addresses. If it keeps failing, one side is likely on a symmetric NAT (common on mobile hotspots). |
| Punch succeeds, then `QUIC handshake` error | Middlebox interference, or the peer process exited mid-handshake | The app retries on its own. If persistent, a middlebox may be mangling the flow — or (manual mode only) check that both sides selected **opposite** roles. |
| `role misconfiguration: both sides selected '…'` | Both machines selected the same role | Re-select one of them at the setup screen — `server` exposes, `client` offers a local port. |
| `… is required for the … role` error at startup | Your config is missing the key for the role you selected | Add `remote_target_addr` (server) or `local_tcp_listen_port` (client) — easiest: set **both** in every config. |
| Tunnel up, but the target connection dies instantly (client sees EOF) | The exposed service isn't reachable from the server machine | Test locally on the server machine (`nc 127.0.0.1 22`); fix the target. The server logs a `cannot reach target; closing stream` warning. The tunnel itself stays up for other connections. |
| `bind local TCP listener … (is the port already in use?)` | The local port is taken by another process (or a zombie previous run) | Pick another `local_tcp_listen_port`, or kill the old process. |
| Telegram mode falls back to manual | Bad token, bot-to-bot communication not enabled on one of the bots, or wait timeout | Check the `[telegram]` table (token is *this* machine's, `peer_bot_id` is the *peer bot's*), enable bot-to-bot communication on **both** bots, check `timeout_secs`. Manual mode keeps working either way. |

General debug moves:

- `--verbose` (or `LOG_LEVEL=debug`) on **both** sides: you'll see each
  punch packet, each STUN round, and exactly where things stop.
- Confirm the **role lines** point the tunnel the direction you expect.

## Limitations

- **IPv4 only** for the punched socket (`0.0.0.0` bind). IPv6 would need no
  punching at all — it's a future item.
- **Simultaneous hole punching works best against *cone* NATs.** Symmetric
  NATs / CGNAT (common on mobile hotspots) will typically fail the punch
  within the timeout — a TURN relay fallback is on the roadmap.
- **One local port (client) and one target service (server) per side** at a
  time (though concurrent *connections* through them are fully supported).
- **No mid-tunnel role switch.** Roles are fixed per run; to swap
  directions, quit and re-select (the re-negotiation flow picks up fresh
  after that).
- **MVP trust model** (accept-any cert) — see [Security model](#security-model).
- **Windows TUI** needs the optional `windows-curses` extra; without it the
  app runs in plain-log mode.

## Development

```sh
python3 -m venv .venv
.venv/bin/pip install -e .

.venv/bin/python -m compileall -q p2p_tunnel tests   # everything compiles
.venv/bin/python -m unittest discover -s tests -v    # full test suite (unittest only)

# opt-in live STUN check against stun.l.google.com:
PTUN_LIVE_STUN=1 .venv/bin/python -m unittest discover -s tests -p "test_stun.py"

.venv/bin/p2p-tunnel --no-tui --verbose   # run with debug logging
```

**Tests** are stdlib `unittest` (no pytest, no test-only dependencies) and
track the Rust test suite 1:1 where the behavior is ported: STUN
encode/parse (incl. edge cases: unknown attrs, wrong transaction IDs,
v4/v6), punch timing/filtering/timeout, cert/fingerprint construction, and
the bridge's copy + half-close semantics (via in-memory duplex streams).
Telegram classification is tested against the local
[`tests/telegram/mock_bot_api.py`](tests/telegram/mock_bot_api.py) mock Bot
API; `tests/nat-sim/` holds helpers for a local two-NAT simulation
(network namespaces + iptables): a fake STUN server that *is* the NAT, a
TCP echo target, and a probe client.

Unlike the Rust tool, the Python port **does** loopback-test the QUIC
server+client path — `aioquic`'s
`create_datagram_endpoint(sock=…)` makes pre-bound-socket reuse
deterministic, so the loopback handshake + stream round-trip is a real
unittest.

The Rust `main` branch is the **behavior oracle**: where this branch and
`main` disagree about the *internals* of a step, `main` wins; where they
disagree about *orchestration* (role selection, default channel,
reconnect), PLAN.md §2 (D1–D6) wins.

### Repository layout

```
.
├── config.toml                # sample configuration
├── PLAN.md                    # the plan (incl. v2 divergences D1–D6)
├── PROGRESS.md                # implementation scratchpad — phase-by-phase state
├── pyproject.toml             # aioquic is the only runtime dependency
├── p2p_tunnel/
│   ├── __init__.py            # version
│   ├── __main__.py            # python -m p2p_tunnel
│   ├── main.py                # entry point; the full pipeline (Phases 10–11)
│   ├── config.py              # Config.load (tomllib)
│   ├── cli.py                 # argparse CLI + peer-address prompt/parsing
│   ├── stun.py                # manual RFC 5389 client + the shared UdpSocket
│   ├── punch.py               # hole punching loop
│   ├── quic.py                # certs, aioquic configs, endpoint attach over
│   │                          #   the reused socket, keep-alive
│   ├── tunnel.py              # TCP↔QUIC bridges (client + server sides)
│   ├── role.py                # roles + conflict checks (Phase 9)
│   ├── telegram.py            # Telegram channel, PTUN v1.1 (Phase 8)
│   ├── tui.py / tui_state.py  # curses TUI + shared state (Phase 12)
└── tests/
    ├── test_config.py / test_cli.py / test_stun.py / test_punch.py /
    │   test_quic.py / test_tunnel.py / test_role.py / test_telegram.py
    ├── telegram/mock_bot_api.py  # mock Telegram Bot API for the exchange tests
    └── nat-sim/               # two-NAT simulation: fake STUN/NAT, echo, probe
```

## License

MIT — see `LICENSE`.
