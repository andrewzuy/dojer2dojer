"""Command-line interface and the interactive peer-address prompt
(port of the Rust ``src/cli.rs``).

The prompt loop is deliberately decoupled from *how* input is read: the
caller injects a ``read`` callable returning the next :class:`PromptOutcome`
(plain stdin in the log path, the TUI's inline editor when the TUI is on).
That keeps the loop pure and unit-testable, exactly as in the Rust version.
"""

from __future__ import annotations

import argparse
import ipaddress
import sys
from dataclasses import dataclass
from pathlib import Path

from p2p_tunnel import __version__

PROMPT_TEXT = "Enter peer's public address (ip:port): "


class Cli:
    """Parsed command-line arguments (clap → argparse)."""

    def __init__(
        self,
        config: Path,
        verbose: bool = False,
        telegram: bool = False,
        tui: bool = False,
        no_tui: bool = False,
    ) -> None:
        self.config = config
        self.verbose = verbose
        self.telegram = telegram
        self.tui = tui
        self.no_tui = no_tui

    @classmethod
    def parse(cls, argv: list[str] | None = None) -> "Cli":
        parser = argparse.ArgumentParser(
            prog="p2p-tunnel",
            description=(
                "P2P NAT-traversal tunnel over QUIC: reach a private TCP "
                "service on another machine behind NAT, with no open ports "
                "and no relay server."
            ),
        )
        parser.add_argument(
            "--config",
            default="./config.toml",
            type=Path,
            metavar="PATH",
            help="path to the TOML config file (default: ./config.toml)",
        )
        parser.add_argument(
            "--verbose",
            action="store_true",
            help="enable debug logging (P2P_TUNNEL_LOG/RUST_LOG take precedence if set)",
        )
        parser.add_argument(
            "--telegram",
            action="store_true",
            help=(
                "start in Telegram address-exchange mode: the bots DM each "
                "other's public addresses automatically (requires the "
                "[telegram] config table and Bot-to-Bot Communication Mode "
                "for both bots); `t` in the TUI toggles the mode at any time"
            ),
        )
        parser.add_argument(
            "--tui", action="store_true", help="show the live terminal UI (auto-enabled on a TTY)"
        )
        parser.add_argument(
            "--no-tui",
            action="store_true",
            help="force the plain log output, even when attached to a TTY",
        )
        parser.add_argument(
            "-V",
            "--version",
            action="version",
            version=f"%(prog)s {__version__}",
        )
        ns = parser.parse_args(argv)
        return cls(
            config=ns.config,
            verbose=ns.verbose,
            telegram=ns.telegram,
            tui=ns.tui,
            no_tui=ns.no_tui,
        )


class PromptBail(Exception):
    """Why :func:`prompt_peer_addr` stopped without producing an address."""


class ModeToggled(PromptBail):
    """The user switched the address-exchange mode mid-prompt (the `t` key)."""


class Aborted(PromptBail):
    """The user aborted the prompt (q / Esc / Ctrl-C) or the read failed."""


class Eof(PromptBail):
    """stdin was closed (EOF)."""


@dataclass(frozen=True)
class PromptOutcome:
    """One read of user input through the active transport.

    ``line`` is ``None`` for the non-line outcomes; the flags are mutually
    exclusive. (Lives here — not in the TUI — because it is the contract
    between the pipeline's prompt loop and whichever transport reads input.)
    """

    line: str | None = None
    mode_toggled: bool = False
    aborted: bool = False
    eof: bool = False

    @classmethod
    def from_line(cls, line: str) -> "PromptOutcome":
        return cls(line=line)

    @classmethod
    def mode_toggled_outcome(cls) -> "PromptOutcome":
        return cls(mode_toggled=True)

    @classmethod
    def aborted_outcome(cls) -> "PromptOutcome":
        return cls(aborted=True)

    @classmethod
    def eof_outcome(cls) -> "PromptOutcome":
        return cls(eof=True)


def prompt_peer_addr(read) -> tuple[str, int]:
    """Read the peer's public address from the user, re-prompting until valid.

    ``read`` is a zero-argument callable returning the next
    :class:`PromptOutcome`. Raises :class:`ModeToggled`, :class:`Aborted` or
    :class:`Eof` (all :class:`PromptBail`) when the loop bails.

    One-shot interactive prompt: briefly blocking the async runtime on input
    is acceptable here (the pipeline is otherwise idle waiting for this).
    """
    while True:
        try:
            outcome = read()
        except OSError:
            raise Aborted() from None
        if outcome.mode_toggled:
            raise ModeToggled() from None
        if outcome.aborted:
            raise Aborted() from None
        if outcome.eof:
            raise Eof() from None
        line = (outcome.line or "").strip()
        if not line:
            print("Address cannot be empty, please try again.", file=sys.stderr)
            continue
        try:
            return parse_peer_addr(line)
        except PeerAddrError as e:
            print(f"Invalid address '{line}': {e}. Please try again.", file=sys.stderr)


class PeerAddrError(ValueError):
    """The peer-address string is not a valid ``ip:port``."""


def parse_peer_addr(input: str) -> tuple[str, int]:
    """Parse a ``ip:port`` (or ``[v6]:port``) string into ``(host, port)``.

    Mirrors Rust's ``SocketAddr::from_str``: IPv4 and IPv6 literals, port
    required, port in 1..65535. Raises :class:`PeerAddrError`.
    """
    s = input.strip()
    try:
        if s.startswith("["):
            # IPv6 literal form: [2001:db8::1]:443
            end = s.rfind("]:")
            if end == -1:
                raise ValueError("unterminated IPv6 address")
            host = str(ipaddress.ip_address(s[1:end]))
            port = int(s[end + 2 :])
        else:
            host_s, _, port_s = s.rpartition(":")
            if not host_s:
                raise ValueError("missing host")
            host = str(ipaddress.ip_address(host_s))
            port = int(port_s)
        if not 1 <= port <= 65535:
            raise ValueError("port out of range")
        return host, port
    except ValueError as e:
        raise PeerAddrError(str(e) or "invalid address") from None


def read_line_stdin(prompt: str = PROMPT_TEXT) -> PromptOutcome:
    """Plain-stdin transport for the prompt loop (used when the TUI is off)."""
    try:
        print(prompt, end="", flush=True)
        line = sys.stdin.readline()
    except OSError:
        return PromptOutcome.aborted_outcome()
    if line == "":
        return PromptOutcome.eof_outcome()
    return PromptOutcome.from_line(line)
