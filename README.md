# p2p-tunnel (Python)

> ⚠️ **This branch is a work in progress.** It rewrites the Rust
> `p2p-tunnel` (on `main`) in Python. See **[PLAN.md](PLAN.md)** for the
> full port plan and **[PROGRESS.md](PROGRESS.md)** for the development
> log.

The goal: the same P2P NAT-traversal tunnel — two machines behind NATs
reach each other's private TCP services over a QUIC byte pipe, with no
open ports and no relay server — written in Python with **one**
third-party dependency (`aioquic` for QUIC/TLS 1.3); everything else is
the standard library.

Until Phase 16 the `README` is a stub; the Rust `main` branch README
documents the (still-accurate) behavior of the reference implementation.

```
pip install -e .        # inside a venv; Python >= 3.11
p2p-tunnel --help       # works from Phase 0; the full pipeline lands per PLAN.md
```
