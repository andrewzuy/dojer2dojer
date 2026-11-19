"""Command-line interface, the interactive peer-address prompt (port of
the Rust ``src/cli.rs``), and the v2 additions: exchange-mode resolution
(D2) and the S1 setup prompts (role + role-specific setting, D1/D5).

The prompt loops are deliberately decoupled from *how* input is read: the
caller injects a ``read`` callable returning the next :class:`PromptOutcome`
(plain stdin in the log path, the TUI's inline editor when the TUI is on).
That keeps the loops pure and unit-testable, exactly as in the Rust version.
"""

from __future__ import annotations

import argparse
import enum
import ipaddress
import sys
from dataclasses import dataclass
from pathlib import Path

from p2p_tunnel import __version__
from p2p_tunnel.config import Config, ConfigError, validate_for_role
from p2p_tunnel.role import Role

PROMPT_TEXT = "Enter peer's public address (ip:port): "
ROLE_PROMPT_TEXT = "Role (client/server) [client]: "


class Cli:
    """Parsed command-line arguments (clap → argparse)."""

    def __init__(
        self,
        config: Path,
        verbose: bool = False,
        telegram: bool = False,
        manual: bool = False,
        tui: bool = False,
        no_tui: bool = False,
    ) -> None:
        self.config = config
        self.verbose = verbose
        self.telegram = telegram
        self.manual = manual
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
                "force the Telegram address-exchange mode: the bots DM each "
                "other's public addresses automatically (requires the "
                "[telegram] config table and Bot-to-Bot Communication Mode "
                "for both bots); `t` in the TUI toggles the mode at any time"
            ),
        )
        parser.add_argument(
            "--manual",
            "--no-telegram",
            dest="manual",
            action="store_true",
            help=(
                "force the manual address-exchange mode (type the peer's "
                "public address; no Telegram bots involved)"
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
            manual=ns.manual,
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


# ---------------------------------------------------------------------------
# v2: exchange-mode resolution (D2)
# ---------------------------------------------------------------------------


class ExchangeMode(enum.Enum):
    """How the two peers exchange public addresses (PLAN §5.7, D2)."""

    #: Bots DM each other's addresses via the Telegram channel.
    TELEGRAM = "telegram"
    #: The operator types the peer's public address at the prompt.
    MANUAL = "manual"


class ExchangeModeError(Exception):
    """The CLI flags cannot be reconciled with the config into a mode."""


def resolve_exchange_mode(cli: Cli, cfg: Config) -> ExchangeMode:
    """Resolve the address-exchange mode (pure, unit-tested; PLAN D2).

    * ``--manual`` / ``--no-telegram`` → :attr:`ExchangeMode.MANUAL`
      (the ``[telegram]`` table is irrelevant, if present it is ignored)
    * ``--telegram`` → :attr:`ExchangeMode.TELEGRAM`, or
      :class:`ExchangeModeError` when the config has no ``[telegram]``
      table (error with hint, per the v2 CLI table)
    * no flag → **Telegram if a ``[telegram]`` table is configured, else
      manual** (D2: Telegram is the default when available)
    """
    if cli.manual:
        return ExchangeMode.MANUAL
    if cfg.telegram is None:
        if cli.telegram:
            raise ExchangeModeError(
                "--telegram was given but the config has no [telegram] "
                "table (token, peer_bot_id, secret) — add one to the "
                "config, or drop --telegram to use the manual address "
                "prompt"
            )
        return ExchangeMode.MANUAL
    return ExchangeMode.TELEGRAM


# ---------------------------------------------------------------------------
# v2: S1 setup — role + role-specific setting (D1, D5)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Setup:
    """The resolved S1 setup state: role + the role-specific setting.

    ``local_port`` is set for the client role (the 127.0.0.1 listen port,
    D6); ``target`` is set for the server role (the service to expose,
    ``ip:port``). The unused field is ``None``.
    """

    role: Role
    local_port: int | None = None
    target: tuple[str, int] | None = None


def prompt_role(read) -> Role:
    """Ask which role this side plays (S1, D1). Default: :attr:`Role.CLIENT`.

    Accepts ``client``/``c`` and ``server``/``s`` (case-insensitive); an
    empty line takes the default. Re-prompts on anything else.
    ``read`` is the :class:`PromptOutcome` transport (same contract as
    :func:`prompt_peer_addr`); the usual :class:`PromptBail` subclasses
    (mode toggle / abort / EOF) are raised unchanged.
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
            return Role.CLIENT
        choice = line.lower()
        if choice in ("client", "c"):
            return Role.CLIENT
        if choice in ("server", "s"):
            return Role.SERVER
        print(
            f"Invalid role '{line}': please enter 'client' or 'server'.",
            file=sys.stderr,
        )


def prompt_local_port(read, prefilled: int | None = None) -> int:
    """Ask for the client's local TCP listen port (S1, D5/D6).

    An empty line takes the ``prefilled`` value (from the config); with no
    prefill an empty line re-prompts. Re-prompts on an invalid value.
    Same ``read``/bail contract as :func:`prompt_role`.
    """
    while True:
        if prefilled is not None:
            prompt = f"Local TCP port (127.0.0.1) [{prefilled}]: "
        else:
            prompt = "Local TCP port (127.0.0.1): "
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
            if prefilled is not None:
                return prefilled
            print("Port cannot be empty, please try again.", file=sys.stderr)
            continue
        try:
            port = int(line)
        except ValueError:
            port = None
        if port is None or not 1 <= port <= 65535:
            print(
                f"Invalid port '{line}': expected a number between 1 and 65535.",
                file=sys.stderr,
            )
            continue
        return port


def prompt_server_target(read, prefilled: str | None = None) -> tuple[str, int]:
    """Ask for the service the server role exposes, ``ip:port`` (S1, D5).

    An empty line takes the ``prefilled`` value (from the config, re-parsed
    — an invalid prefill re-prompts instead of crashing); with no prefill
    an empty line re-prompts. Re-prompts on an invalid value. Same
    ``read``/bail contract as :func:`prompt_role`.
    """
    while True:
        if prefilled is not None:
            prompt = f"Service to expose (ip:port) [{prefilled}]: "
        else:
            prompt = "Service to expose (ip:port): "
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
            if prefilled is not None:
                try:
                    return parse_peer_addr(prefilled)
                except PeerAddrError as e:
                    print(
                        f"The configured remote_target_addr '{prefilled}' is "
                        f"invalid ({e}); please enter the service to expose "
                        "(ip:port).",
                        file=sys.stderr,
                    )
                    continue
            print("Target address cannot be empty, please try again.", file=sys.stderr)
            continue
        try:
            return parse_peer_addr(line)
        except PeerAddrError as e:
            print(f"Invalid address '{line}': {e}. Please try again.", file=sys.stderr)


def resolve_setup(cfg: Config, read, *, interactive: bool) -> Setup:
    """S1 setup (D5) in its plain (stdin-transport) form.

    Interactive: :func:`prompt_role` (default client), then the
    role-specific setting prompt with the config value prefilled. The
    resolved values live in the returned :class:`Setup` (the config file
    is not modified).

    Non-interactive: no prompts are possible, so the role is inferred from
    the config — exactly one of the two role keys must be set
    (``local_tcp_listen_port`` ⇒ client, ``remote_target_addr`` ⇒ server);
    otherwise a :class:`ConfigError` names the missing/ambiguous choice.
    A set-but-invalid ``remote_target_addr`` is also a :class:`ConfigError`
    here (there is no one to re-prompt).
    """
    if interactive:
        role = prompt_role(read)
        if role is Role.CLIENT:
            port = prompt_local_port(read, cfg.local_tcp_listen_port)
            return Setup(role=role, local_port=port)
        host, port = prompt_server_target(read, cfg.remote_target_addr)
        return Setup(role=role, target=(host, port))

    has_client = cfg.local_tcp_listen_port is not None
    has_server = cfg.remote_target_addr is not None
    if has_client and has_server:
        raise ConfigError(
            "cannot determine the role non-interactively: both "
            "`local_tcp_listen_port` (client) and `remote_target_addr` "
            "(server) are set — run interactively to pick a role"
        )
    if has_client:
        role = Role.CLIENT
    elif has_server:
        role = Role.SERVER
    else:
        raise ConfigError(
            "cannot determine the role non-interactively: set "
            "`local_tcp_listen_port` (client) or `remote_target_addr` "
            "(server) in the config, or run interactively to pick a role"
        )
    validate_for_role(cfg, role)
    if role is Role.SERVER:
        try:
            target = parse_peer_addr(cfg.remote_target_addr)
        except PeerAddrError as e:
            raise ConfigError(
                f"config: `remote_target_addr` {cfg.remote_target_addr!r} is "
                f"invalid ({e})"
            ) from None
        return Setup(role=role, target=target)
    return Setup(role=role, local_port=cfg.local_tcp_listen_port)
