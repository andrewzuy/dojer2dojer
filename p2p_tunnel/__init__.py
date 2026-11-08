"""p2p-tunnel: P2P NAT-traversal tunnel in Python.

Two machines behind NATs reach each other's private TCP services without
opening ports or running a relay:

    STUN discovery -> address exchange (manual or Telegram bot-to-bot)
    -> simultaneous UDP hole punching -> deterministic peer role
    -> fresh self-signed cert -> QUIC/TLS 1.3 byte pipe over the punched
    socket -> TCP<->QUIC stream bridge.

This is a Python port of the Rust implementation (kept on the `main`
branch), which remains the reference implementation. See PLAN.md for the
port plan and PROGRESS.md for the development log.

Only one direct third-party dependency: `aioquic` (QUIC + TLS 1.3).
Everything else is the standard library (asyncio, tomllib, urllib,
curses, ssl, hashlib, ...).
"""

__version__ = "0.1.0"
