"""Command-line entry point (Phase 1 stub — pipeline lands per PLAN.md).

Phase 0/1: parses the real CLI, explains the current porting state.
Phases 2–13 replace the body of :func:`main` with the full pipeline
(config load, TUI setup, STUN, exchange, punch, role, QUIC, tunnel).
"""

from __future__ import annotations

import sys

from p2p_tunnel import __version__
from p2p_tunnel.cli import Cli


def main(argv: list[str] | None = None) -> int:
    cli = Cli.parse(argv)
    print(
        f"p2p-tunnel {__version__} (python port, branch `python`)\n"
        "The pipeline is being ported phase by phase — see PLAN.md and "
        "PROGRESS.md in the repository.\n"
        f"(parsed args: config={cli.config}, telegram={cli.telegram}, "
        f"tui={cli.tui}, no_tui={cli.no_tui}, verbose={cli.verbose})",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
