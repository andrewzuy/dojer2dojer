# p2p-tunnel

[![CI](https://github.com/andrewzuy/dojer2dojer/actions/workflows/ci.yml/badge.svg)](https://github.com/andrewzuy/dojer2dojer/actions/workflows/ci.yml)

A small Rust CLI that lets two machines behind NATs reach each other's
**private TCP services** — no ports to open, no relay server, no account.

Type one address into the other machine, and a normal TCP tool (`ssh`,
`nc`, `curl`, …) works as if the two machines were on the same LAN.

- **STUN** (RFC 5389, hand-rolled) discovers each machine's public `ip:port`
- **Simultaneous UDP hole punching** opens the NAT hole
- **QUIC / TLS 1.3** (quinn) carries an encrypted, reliable byte pipe over the hole
- A **TCP↔QUIC stream bridge** turns the pipe into ordinary TCP connections

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
2. [The one rule: which side exposes the service](#the-one-rule-which-side-exposes-the-service)
3. [Requirements](#requirements)
4. [Building](#building)
5. [Quick start (two machines, SSH to a home server)](#quick-start)
6. [Automatic address exchange over Telegram](#automatic-address-exchange-over-telegram)
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

Everything below happens on **both** machines, in the same order, with no
coordination beyond you typing an address into the other party's terminal:

### 1. STUN discovery

A raw RFC 5389 **Binding Request** is sent from THE socket to each configured
STUN server (manual implementation — no STUN crate, because the socket must
stay under our control for the later phases). Each server gets up to 3 s, and
the whole list is tried twice. The response's `XOR-MAPPED-ADDRESS` attribute
tells us the public `ip:port` the rest of the internet sees for this socket.

### 2. Peer address exchange

Your public address is printed. Two ways to complete the exchange:

- **Manual (default):** share your address with the other person (chat, phone,
  carrier pigeon) and type *their* address into the prompt. Input is validated
  and re-prompted on bad input.
- **Automatic over Telegram:** run with `--telegram` and a configured
  `[telegram]` table, and the two bots DM each other their public addresses
  instead — no copy/paste. See [Automatic address exchange over
  Telegram](#automatic-address-exchange-over-telegram).

> **Addresses are session-scoped.** The port (and sometimes the IP) changes
> every time the process runs, and the NAT mapping goes away when the process
> exits or the binding expires. There is no persistent "tunnel address" —
> exchange a fresh address for every session.

### 3. UDP hole punching

Both sides repeatedly send a small UDP packet (a random 8-byte session
nonce) to the peer's public address, every `punch_interval_ms`
(default 500 ms). The moment a packet **from the peer's exact address**
arrives, the punch has succeeded on that side; anything from other senders is
ignored. Packets are sent for up to `punch_timeout_secs` (default 30 s).
Because both sides punch at the same time, typical cone NATs open within a
few seconds of both processes starting.

### 4. Deterministic role negotiation

QUIC needs one peer to *listen* (server) and one to *dial* (client). To avoid
any extra signaling, both sides run the **same pure function** on the two
public addresses:

- lower public IP → **server** role (hosts the QUIC endpoint)
- higher public IP → **client** role (dials in)
- all IPv4 addresses sort before IPv6 (the socket is IPv4-only in this MVP,
  so this rarely matters)
- same IP (local testing) → lower port wins

The function always returns *opposite* roles on each side, so both machines
agree on who is who without talking.

### 5. Self-signed certificate + QUIC handshake

A fresh **ECDSA P-256 self-signed certificate** (CN `p2p-tunnel`) is
generated in memory once the role is known. The server presents it; the client accepts
*any* certificate — see the [security model](#security-model) for what that
means in practice. **Both sides log the certificate's SHA-256 fingerprint** so
the two humans can compare it out-of-band, exactly like an SSH host-key
fingerprint.

The punched UDP socket is then handed to quinn, which takes ownership and
performs the TLS 1.3 / QUIC handshake over it.

### 6. TCP↔QUIC stream bridge

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

When the QUIC connection drops, everything shuts down cleanly and the process
exits — re-run both sides to make a new tunnel (no automatic reconnect yet).

---

## The one rule: which side exposes the service

This is the part that surprises first-time users, so read it before you
configure:

> **The machine with the *lower* public IP becomes the *server* role — and it
> is the server role that forwards traffic to `remote_target_addr`.**
>
> In other words: **tunneled traffic is always delivered to the machine with
> the lower public IP.** The other machine (higher IP) is the one that gets
> the local convenience port (`127.0.0.1:<local_tcp_listen_port>`).

Consequences:

- To reach a service on your home box from a laptop, the **home box needs the
  lower public IP**. You can check before committing: each run prints its
  public address in step 1, and the role is logged right after the punch.
- If the ordering comes out the other way, the tunnel still works — it just
  exposes *the other machine's* target service. Reconfigure your goal to
  match the direction (or see [Limitations](#limitations) — role override is
  a known future item).

**Tip that removes most of the fiddling:** put *both* keys in *every*
machine's config — `local_tcp_listen_port` (the port *this* machine will
offer) and `remote_target_addr` (the private service *on this* machine).
Each side only reads the key that matches the role it happens to get, so you
don't have to predict which role you'll be.

---

## Requirements

- **Rust** (edition 2024; tested with cargo 1.93) — or grab a
  [CI-built static Linux binary](#building)
- **Outbound UDP** to a STUN server (default config uses Google/Cloudflare)
  and to the peer's public address
- **Two machines whose NATs are not symmetric** (see
  [Limitations](#limitations))
- For real use: a way to compare the two addresses out-of-band (any chat)

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

**Home box** (`config.toml`):

```toml
stun_servers = [
    "stun.l.google.com:19302",
    "stun.cloudflare.com:3478",
]

# This machine's local port, used if THIS machine ends up the client role.
local_tcp_listen_port = 12345

# The private service on THIS box to expose (used if THIS machine ends up
# the server role). Here: SSH on loopback.
remote_target_addr = "127.0.0.1:22"
```

**Laptop** (`config.toml`):

```toml
stun_servers = [
    "stun.l.google.com:19302",
    "stun.cloudflare.com:3478",
]

# The port the laptop will offer, e.g. ssh -p 12345 user@127.0.0.1
local_tcp_listen_port = 12345

# A valid private target reachable FROM THE LAPTOP — only ever read if the
# laptop turns out to be the server role (i.e. the laptop has the lower
# public IP). Point it at something harmless on your LAN.
remote_target_addr = "192.168.1.50:8080"
```

(See [The one rule](#the-one-rule-which-side-exposes-the-service) for why the
laptop needs a `remote_target_addr` at all, and [Configuration
reference](#configuration-reference-configtoml) for every key.)

### Step 3 — run on both machines

```sh
# home box
./target/release/p2p-tunnel
# laptop
./target/release/p2p-tunnel
```

Each prints its public address; exchange them and type each one into the
other's prompt:

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
success. **Check the role lines** — the home box must be the *server*:

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

## Automatic address exchange over Telegram

The manual "type the address" prompt is the default and always works. If you'd
rather not copy/paste between two terminals, both machines can exchange
addresses automatically using Telegram's [bot-to-bot](https://core.telegram.org/api/bots/bot-to-bot)
capability — each side's bot DMs the other side's bot a self-describing
`PTUN v1 <ip:port>` message, and each waits for the peer's to arrive.

This is **optional**: nothing changes unless you add the `[telegram]` table
*and* pass `--telegram`. The manual prompt remains the fallback whenever
`--telegram` isn't set, the table is missing, the token is invalid, or the
wait times out.

### Set it up

1. Create **two** bots in [@BotFather](https://t.me/BotFather) (one per
   machine) and note each one's **API token** (`123456:ABC-DEF…`).
2. On **each** bot: BotFather → *Bot Settings* → *Bot-to-Bot Communication*
   → **Enable**. Without this, `sendMessage` to a bot returns
   `USER_BOT_TO_BOT_DISABLED`.
3. Get each bot's **numeric id** (BotFather can show it, or any `@id` bot on
   the bot's profile).
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
5. Run both sides with the flag:

   ```sh
   ./p2p-tunnel --telegram
   ```

   Each side sends its address and waits (up to `timeout_secs`) for the
   peer's. On success it proceeds straight to hole punching; on timeout or
   error it logs the reason and drops back to the manual prompt.

### How it stays loop-safe

Bots replying to bots can ping-pong forever. This implementation prevents
that:

- It **only ever sends once** — its own address — and never auto-replies to
  incoming `PTUN` messages.
- It **ignores its own echoes** (messages whose `from.id` is its own bot
  id), so the reply it receives isn't treated as a new peer.
- It only accepts a `PTUN v1` payload from the **specific peer bot id**
  configured; messages from any other sender are discarded.

The payload format is `PTUN v1 <ip:port>`; anything not matching that prefix
is ignored. Role negotiation (server vs client) is unchanged and still
computed locally from the two addresses — Telegram only carries the addresses
themselves.

## Configuration reference (`config.toml`)

The file is optional to *find* (`--config` selects it, default `./config.toml`)
but required to *exist*. Note that **unknown keys are silently ignored** —
typing a key name wrong won't error out, so copy the shipped sample.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `stun_servers` | `["host:port", …]` | *(required, non-empty)* | STUN servers tried in order (hostnames OK, port defaults to 19302 if omitted). Each gets up to 3 s; the whole list is tried twice. |
| `punch_interval_ms` | `u64` | `500` | Milliseconds between outbound hole-punch packets. |
| `punch_timeout_secs` | `u64` | `30` | Give up on hole punching after this long (the error includes how many packets were sent). |
| `keep_alive_interval_secs` | `u64` | `5` | Seconds between QUIC keep-alive PING packets sent while the tunnel is idle. Idle NAT devices drop the port mapping of a silent connection, so these small PINGs keep the tunnel alive; `0` disables keep-alive (the tunnel then dies after the NAT's idle timeout, typically a few minutes). |
| `local_tcp_listen_port` | `u16` | unset | **Read only if this machine gets the client role.** The `127.0.0.1` port that offers the tunnel (e.g. `12345`). Loopback only — never exposed to your LAN. |
| `remote_target_addr` | `"ip:port"` | unset | **Read only if this machine gets the server role.** The private TCP target on *this* machine's network that tunneled traffic is delivered to (e.g. `"127.0.0.1:22"`). |
| `[telegram].token` | `string` | unset | **Only used with `--telegram`.** This machine's bot API token. The whole `[telegram]` table is optional and ignored unless the flag is passed. |
| `[telegram].peer_bot_id` | `i64` | unset | The **peer bot's** numeric id — the `chat_id` its `PTUN` address message is sent to. |
| `[telegram].timeout_secs` | `u64` | `120` | How long to wait for the peer bot's address before falling back to the manual prompt. |

The shipped sample `config.toml` (in the repo root) has both role keys and
the `[telegram]` table commented out with instructions; copy it and edit.

## CLI reference

```
p2p-tunnel [OPTIONS]

Options:
      --config <CONFIG>  Path to the TOML config file [default: ./config.toml]
      --telegram         Negotiate the peer address via Telegram bot-to-bot
                         (requires a `[telegram]` table in the config); falls
                         back to the manual prompt on timeout/error
      --verbose          Enable debug logging (RUST_LOG takes precedence if set)
  -h, --help             Print help
  -V, --version          Print version
```

Logging levels: `info` by default (the lines shown in the quick start),
`--verbose` or `RUST_LOG=debug` for per-packet/per-round detail (every punch
packet sent, every ignored non-peer packet, STUN round timing, …).

On success the process exits 0 when the tunnel ends; on failure it prints
`error: <details>` plus an actionable `hint:` line to stderr and exits 1.

---

## Examples

### SSH to a home server (the canonical use case)

As in the [quick start](#quick-start): laptop's `config.toml` has
`local_tcp_listen_port = 12345`, home box has
`remote_target_addr = "127.0.0.1:22"`, then on the laptop:

```sh
ssh -p 12345 user@127.0.0.1
```

Works with any SSH option: `scp -P 12345 user@127.0.0.1:/path/file .`,
`ssh -p 12345 -L 8080:localhost:8080 user@127.0.0.1`, etc.

### `nc` / any plain TCP service

Expose a private HTTP server, a game port, a database, anything:

```toml
# machine with the lower public IP (server role)
remote_target_addr = "192.168.1.20:8080"
```

```sh
# other machine (client role, local_tcp_listen_port = 18080)
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
  fingerprint of the certificate in use at startup (the line shown in the
  quick start). Compare them out-of-band — the same way you'd compare an SSH
  host key — and a MITM is detected.
- **The local listener is loopback-only** (`127.0.0.1`), so devices on your
  LAN can't reach the tunnel port directly.
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
| `… is required for the … role` error at startup | Your config is missing the key for the role this machine got | Add `remote_target_addr` (server role) or `local_tcp_listen_port` (client role) — easiest: set **both** in every config, per the [tip](#the-one-rule-which-side-exposes-the-service). |
| Tunnel up, but the target connection dies instantly (client sees EOF) | `remote_target_addr` isn't reachable from the server machine | Test locally on the server machine (`nc 127.0.0.1 22`); fix the target, then re-run. The server logs a `cannot reach target; closing stream` warning. |
| `bind local TCP listener … (is the port already in use?)` | The local port is taken by another process (or a zombie previous run) | Pick another `local_tcp_listen_port`, or kill the old process. |
| It worked once and never again | NAT bindings / public addresses are ephemeral; some NATs age out mappings quickly | Always start both sides fresh and exchange fresh addresses per session. |

General debug moves:

- `--verbose` (or `RUST_LOG=debug`) on **both** sides: you'll see each punch
  packet, each STUN round, and exactly where things stop.
- `RUST_LOG=trace` on one side for maximum noise.
- Confirm the **role lines** point the tunnel the direction you expect (see
  [The one rule](#the-one-rule-which-side-exposes-the-service)).

## Limitations

- **IPv4 only** for the punched socket (`0.0.0.0` bind). IPv6 would need no
  punching at all — it's a future item.
- **Direction is fixed by address order**: traffic always lands on the
  machine with the lower public IP (no manual role override yet).
- **Simultaneous hole punching works best against *cone* NATs.** Symmetric
  NATs / CGNAT (common on mobile hotspots) will typically fail the punch
  within the timeout — a TURN relay fallback is on the roadmap.
- **One tunnel per run.** No reconnect: if the QUIC connection drops or a
  machine restarts, re-run both sides. Address exchange is manual by default
  (or automatic via the optional Telegram bot-to-bot channel), but there is no
  persistent signaling or re-handshake once a tunnel is down. Multiplexing
  refinements and resilience are future work.
- **One listen port and one target per side** (though concurrent
  *connections* through them are fully supported).
- **MVP trust model** (accept-any cert) — see [Security model](#security-model).

## Development

```sh
cargo build                # compile
cargo test                 # 24 unit tests
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
cargo run -- --verbose     # run with debug logging
```

**Tests** cover STUN encode/parse (incl. edge cases: unknown attrs, wrong
transaction IDs, v4/v6), punch timing/filtering/timeout, role symmetry
(exhaustive over mixed v4/v6 address sets), cert/fingerprint construction,
and the bridge's copy + half-close semantics (via in-memory `tokio::io`
streams). By project decision there is deliberately **no loopback test of the
QUIC server+client path** (one machine playing both roles is ambiguous); the
real handshake is validated in two-machine tests.

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
├── tests/nat-sim/             # Phase 12 helpers: fake STUN/NAT, echo target, probe client
└── src/
    ├── main.rs                # the full pipeline, one reused UDP socket, error hints
    ├── config.rs              # Config::load (serde/toml)
    ├── cli.rs                 # clap CLI + peer-address prompt/parsing
    ├── stun.rs                # manual RFC 5389 client (encode/parse/discover)
    ├── punch.rs               # hole punching loop
    ├── role.rs                # deterministic server/client decision
    ├── quic.rs                # certs, verifier, endpoint, connect/accept
    ├── tunnel.rs              # TCP↔QUIC bridges (client + server sides)
    └── telegram.rs            # optional Telegram bot-to-bot address exchange
```

The full development plan lives in `plan.md` (repo parent directory);
`PROGRESS.md` tracks what is done and what the next phase needs.

## License

MIT — see `LICENSE`.
