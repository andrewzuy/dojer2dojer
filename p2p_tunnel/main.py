"""Command-line entry point (stub — the full pipeline lands per PLAN.md).

Phase 0 stub: parses `--help` / `-V` and explains the current state.
Phases 1–13 replace this with the real pipeline (config load, TUI setup,
STUN, exchange, punch, role, QUIC, tunnel).
"""

from __future__ import annotations

import argparse
import sys

from p2p_tunnel import __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="p2p-tunnel",
        description=(
            "P2P NAT-traversal tunnel: reach a private TCP service on another "
            "machine behind NAT, with no open ports and no relay server "
            "(STUN + hole punching + QUIC over the punched socket)."
        ),
    )
    parser.add_argument(
        "--config",
        default="config.toml",
        metavar="PATH",
        help="path to the TOML config file (default: ./config.toml)",
    )
    parser.add_argument(
        "--telegram",
        action="store_true",
        help="exchange peer addresses over Telegram bot-to-bot (needs [telegram] in the config)",
    )
    parser.add_argument(
        "--tui",
        action="store_true",
        help="force the live terminal UI (auto-enabled on a TTY)",
    )
    parser.add_argument(
        "--no-tui",
        action="store_true",
        help="disable the live terminal UI (plain log output)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="debug-level log output",
    )
    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    print(
        f"p2p-tunnel {__version__} (python port, branch `python`)\n"
        "The pipeline is being ported phase by phase — see PLAN.md and "
        "PROGRESS.md in the repository.\n"
        f"(parsed args: config={args.config}, telegram={args.telegram}, "
        f"tui={args.tui}, no_tui={args.no_tui}, verbose={args.verbose})",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
