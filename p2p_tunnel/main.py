"""p2p-tunnel entry point — the PLAN §2 pipeline, S0 → T6 (Phase 10, v1).

Wires the phase modules into the single-attempt flow:

    S0  config + CLI, exchange-mode resolution, setup (role + its setting)
    T1  Telegram readiness handshake + role cross-check (or manual fallback, D2)
    T2  STUN discovery on the one UDP socket
    T3  address exchange (Telegram, or the manual prompt)
    T4  simultaneous UDP hole punching (same socket/fd)
    T5  QUIC attach + handshake (same socket/fd — the NAT 4-tuple survives)
    T6  the tunnel bridge, until clean close

v1 (this phase): one attempt. Any failure → the ``error:`` block, an
optional hint, exit code 1. The reconnect supervisor (D3) arrives in
Phase 11 and re-negotiates instead of exiting; the TUI (with its live
reconnect state) lands in Phase 12.
"""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import logging
import os
import re
import socket
import sys
from dataclasses import dataclass
from typing import Any, Callable

from . import quic, stun, tunnel
from .cli import (
    Aborted,
    Cli,
    Eof,
    ExchangeMode,
    ExchangeModeError,
    ModeToggled,
    PromptBail,
    PromptOutcome,
    Setup,
    read_line_stdin,
    prompt_local_port,
    prompt_peer_addr,
    prompt_server_target,
    resolve_exchange_mode,
    resolve_setup,
)
from .config import Config, ConfigError, TelegramConfig, validate_for_role
from .punch import PunchError, punch
from .quic import QuicError
from .role import Role, RoleConflict, check_compatible, role_from_ip_order
from .stun import StunError
from .telegram import TelegramChannel, TelegramError
from .tunnel import ServerEndpoint, TunnelError

log = logging.getLogger("p2p_tunnel.main")

#: T5: how long to wait for the peer's QUIC connection / the client handshake.
QUIC_HANDSHAKE_TIMEOUT_SECS = 30.0


# ---------------------------------------------------------------------------
# Error presentation (Rust `main.rs`: the `error:` block + `hint_for`, ported)
# ---------------------------------------------------------------------------


def error_chain(error: BaseException) -> list[BaseException]:
    """The explicit-cause chain, outermost first (the input to Rust's
    ``format!("{e:#}")`` — ``__cause__`` as set by ``raise ... from``)."""
    chain: list[BaseException] = []
    seen: set[int] = set()
    e: BaseException | None = error
    while e is not None and id(e) not in seen:
        chain.append(e)
        seen.add(id(e))
        e = e.__cause__
    return chain


def format_error(error: BaseException) -> str:
    """Render the chain the way Rust's ``format!("{e:#}")`` does."""
    chain = error_chain(error)
    if len(chain) == 1:
        return str(chain[0])
    parts = [str(chain[0])]
    for cause in chain[1:]:
        parts.append("Caused by:\n    " + str(cause))
    return "\n".join(parts)


def hint_for(error: BaseException, *, attempts: int = 1) -> str | None:
    """A short, actionable hint for the common failure modes.

    Port of the Rust ``hint_for`` — matched on the *full* error chain, not
    just the outermost message — plus the v2 additions (PLAN §4): after
    2+ QUIC-handshake failures the hint gains role advice (the §5.2
    conflict is the most common repeated cause), and role conflicts get
    their own hint. ``attempts`` is the number of pipeline attempts made
    so far (1 in Phase 10; the supervisor feeds it in Phase 11).
    """
    chain = " ".join(str(e) for e in error_chain(error))
    if "STUN discovery failed" in chain:
        return (
            "hint: check internet connectivity and that outbound UDP is not blocked. "
            "If you are behind CGNAT, STUN may report a carrier address you cannot "
            "receive on — this MVP cannot traverse that (see plan: TURN fallback)."
        )
    if "hole punching timed out" in chain:
        return (
            "hint: double-check the peer's address (it goes stale when the peer's NAT "
            "binding expires or they restart). One side may also be behind a symmetric "
            "NAT, which simultaneous UDP punching cannot open — this MVP has no TURN "
            "fallback."
        )
    if "QUIC handshake" in chain:
        if attempts >= 2:
            return (
                "hint: the UDP hole was open but the QUIC/TLS handshake did not "
                "complete. make sure both sides selected opposite roles (one client, "
                "one server). A middlebox may also be interfering, or the peer's "
                "process exited. Retry on both sides."
            )
        return (
            "hint: the UDP hole was open but the QUIC/TLS handshake did not complete. "
            "A middlebox may be interfering, or the peer's process exited. Retry on "
            "both sides."
        )
    if "is required for the" in chain:
        return "hint: add the missing option to your config.toml (see the sample config comments)."
    if "role misconfiguration" in chain:
        return "hint: the two sides must be one client and one server — re-select the role."
    return None


# ---------------------------------------------------------------------------
# Logging setup (Rust main.rs: RUST_LOG / --verbose / INFO; the TUI's own
# log policy is a Phase 12 concern — Phase 10 is always plain log output)
# ---------------------------------------------------------------------------

_LEVEL_TOKENS = {
    "trace": logging.DEBUG,  # no TRACE in stdlib logging; DEBUG is the closest
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "warn": logging.WARNING,
    "warning": logging.WARNING,
    "error": logging.ERROR,
}


def _env_log_level() -> int | None:
    """The level from ``P2P_TUNNEL_LOG``, then ``RUST_LOG`` (the Rust variable
    is honoured for interop familiarity). The last recognised level token
    wins ("p2p_tunnel=debug,other=warn" → WARNING)."""
    for var in ("P2P_TUNNEL_LOG", "RUST_LOG"):
        raw = os.environ.get(var, "")
        if not raw.strip():
            continue
        level: int | None = None
        for token in re.split(r"[,=\s]+", raw.lower()):
            if token in _LEVEL_TOKENS:
                level = _LEVEL_TOKENS[token]
        if level is not None:
            return level
    return None


def setup_logging(verbose: bool) -> None:
    """INFO by default, DEBUG with --verbose; P2P_TUNNEL_LOG / RUST_LOG win."""
    level = _env_log_level()
    if level is None:
        level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        stream=sys.stderr,
    )


def _stdin_interactive() -> bool:
    """S0: are the setup prompts usable? (A real user on the other end of
    stdin — piped/redirected input is non-interactive and errors instead
    of re-prompting forever.)"""
    try:
        return sys.stdin.isatty()
    except (AttributeError, ValueError):
        return False


# ---------------------------------------------------------------------------
# S1 + T1: setup + Telegram readiness handshake + role cross-check (D1/D4)
# ---------------------------------------------------------------------------


@dataclass
class Handshake:
    """The outcome of S1+T1 for one attempt.

    ``final_role`` is ``None`` when the peer declared no role (legacy v1
    peer, or an invalid ROLE line): the role is derived from the IP order
    after T3 (D4) — which is exactly why the derivation happens there.
    """

    setup: Setup
    final_role: Role | None
    channel: TelegramChannel | None
    telegram_usable: bool  # False → T3 must use the manual prompt


async def negotiate_role(
    cfg: Config,
    mode: ExchangeMode,
    *,
    read: Callable[[], PromptOutcome],
    interactive: bool,
    channel_factory: Callable[[TelegramConfig], Any] | None = None,
) -> Handshake:
    """S1 + T1: the setup prompts, then the Telegram readiness handshake and
    role cross-check.

    * Telegram mode: ``READY``/``ROLE`` out, ``READY`` in (the peer must be
      up before either side spends time on STUN), then a 2-second ``ROLE``
      grace (D4). The peer's role is cross-checked against ours — a
      conflict re-enters S1 (interactive: the user re-selects, and the
      channel is re-handshaked) or raises :class:`RoleConflict`
      (non-interactive: a hard error, exit 1).
    * A T1 Telegram failure (channel unusable, or the readiness timeout)
      falls back to the manual exchange (D2): the role is whatever the user
      selected and T3 uses the prompt. The channel stays open on a
      readiness timeout — it is healthy and the next attempt reuses it.
    * Manual mode: no handshake at all.

    ``channel_factory`` is injectable for tests (the real default builds a
    :class:`TelegramChannel`).
    """
    factory = channel_factory or (lambda tc: TelegramChannel(tc))
    channel: Any = None
    while True:
        setup = resolve_setup(cfg, read, interactive=interactive)
        if mode is not ExchangeMode.TELEGRAM or cfg.telegram is None:
            return Handshake(setup, setup.role, None, False)
        try:
            channel = channel or factory(cfg.telegram)
            await channel.start()
        except TelegramError as e:
            log.warning(
                "Telegram signaling unavailable (%s) — falling back to the manual address prompt.",
                e,
            )
            channel.close()
            return Handshake(setup, setup.role, None, False)
        try:
            log.info("exchanging readiness with the peer bot over Telegram…")
            await channel.send_ready(cfg.telegram.secret or "")
            await channel.send_role(setup.role.as_str())
            await channel.wait_ready()
        except TelegramError as e:
            log.warning(
                "Timed out / failed waiting for the peer bot's readiness confirmation "
                "(%s) — switching to the manual address prompt.",
                e,
            )
            return Handshake(setup, setup.role, channel, False)
        peer_role_raw = await channel.wait_role()
        if peer_role_raw is None:
            # Legacy v1 peer: no ROLE line — derive from the IP order after T3 (D4).
            return Handshake(setup, None, channel, True)
        try:
            peer_role = Role.from_str(peer_role_raw)
        except ValueError:
            log.warning("ignoring invalid PTUN ROLE line from the peer: %r", peer_role_raw)
            return Handshake(setup, None, channel, True)
        try:
            check_compatible(setup.role, peer_role)
        except RoleConflict as e:
            role_name = setup.role.as_str()
            print(f"role misconfiguration: both sides are {role_name}", file=sys.stderr)
            hint = hint_for(e)
            if hint is not None:
                print(hint, file=sys.stderr)
            if not interactive:
                raise
            continue  # re-enter S1: the user re-selects the role/setting
        return Handshake(setup, setup.role, channel, True)


# ---------------------------------------------------------------------------
# The attempt: T2 → T6 (one full pass of the §2 flow)
# ---------------------------------------------------------------------------


def _manual_peer_prompt(read: Callable[[], PromptOutcome], own: tuple[str, int]) -> tuple[str, int]:
    """The non-TUI manual address prompt (the Rust wording, verbatim)."""
    print()
    print(f"Your public address is: {stun.fmt_addr(own)}")
    print("Give it to the other party, then enter their public address below.")
    return prompt_peer_addr(read)


def _adopt_role(
    setup: Setup,
    role: Role,
    cfg: Config,
    *,
    read: Callable[[], PromptOutcome],
    interactive: bool,
) -> Setup:
    """After a D4 derivation: make sure the *adopted* role's setting exists.

    The setup was resolved for the *selected* role; when the derived role
    differs, its setting may be missing. Interactive: re-prompt (prefilled
    from the config). Non-interactive: a hard config error.
    """
    if role is Role.SERVER:
        if setup.target is None:
            if interactive:
                host, port = prompt_server_target(read, cfg.remote_target_addr)
                return dataclasses.replace(setup, role=role, target=(host, port))
            validate_for_role(cfg, role)
    else:
        if setup.local_port is None:
            if interactive:
                port = prompt_local_port(read, cfg.local_tcp_listen_port)
                return dataclasses.replace(setup, role=role, local_port=port)
            validate_for_role(cfg, role)
    return setup


async def run_attempt(
    cfg: Config,
    mode: ExchangeMode,
    *,
    read: Callable[[], PromptOutcome],
    interactive: bool,
    channel_factory: Callable[[TelegramConfig], Any] | None = None,
) -> None:
    """One full pass of the §2 flow (S1 → T6) — a single attempt.

    Returns when the tunnel (T6) closes cleanly; the Phase 11 supervisor
    re-negotiates instead of exiting. Any failure (hard or soft) raises —
    Phase 10 maps every failure to a process error (``main``).

    The one UDP socket is created in T2 and reused, untouched, through the
    punch (T4) and the QUIC attach (T5) — the same fd, so the NAT mapping
    and the punched 4-tuple survive.
    """
    hs = await negotiate_role(
        cfg, mode, read=read, interactive=interactive, channel_factory=channel_factory
    )
    channel = hs.channel
    sock: stun.UdpSocket | None = None
    raw_sock: socket.socket | None = None
    endpoint: Any = None
    keep_alive: asyncio.Task | None = None
    try:
        # ── T2 — STUN (the one socket STUN, punch and QUIC all share) ──
        sock = await stun.UdpSocket.create()
        own = await stun.discover_public_addr(sock, cfg.stun_servers)
        log.info("discovered public address: %s", stun.fmt_addr(own))

        # ── T3 — exchange our address, get the peer's ──
        if hs.telegram_usable:
            try:
                await channel.send_addr(own)
                peer = await channel.wait_addr()
            except TelegramError as e:
                log.warning(
                    "Timed out / failed waiting for the peer bot's address (%s) — "
                    "switching to the manual address prompt.",
                    e,
                )
                peer = _manual_peer_prompt(read, own)
        else:
            peer = _manual_peer_prompt(read, own)
        log.info("peer address resolved: %s", stun.fmt_addr(peer))

        # ── role resolution (D4: IP-order derivation when the peer declared none) ──
        setup = hs.setup
        role = hs.final_role
        if role is None:
            role = role_from_ip_order(own, peer)
            if role is not setup.role:
                print(
                    f"warning: the peer did not declare a role; adopting the IP-derived "
                    f"role '{role.as_str()}' (you selected '{setup.role.as_str()}')",
                    file=sys.stderr,
                )
            setup = _adopt_role(setup, role, cfg, read=read, interactive=interactive)
        log.info("role determined: %s", role.as_str())

        # ── T4 — simultaneous hole punching (same socket) ──
        await punch(
            sock, peer, interval_ms=cfg.punch_interval_ms, timeout_secs=cfg.punch_timeout_secs
        )

        # ── T5 — QUIC on the punched socket ──
        if cfg.keep_alive_interval_secs > 0:
            log.info("QUIC keep-alive configured: every %ds", cfg.keep_alive_interval_secs)
        else:
            log.info("QUIC keep-alive configured: disabled")
        cert_der, key, _fingerprint = quic.generate_self_signed_cert()
        if role is Role.SERVER:
            loop = asyncio.get_running_loop()
            first_conn: asyncio.Future = loop.create_future()
            endpoints: list[ServerEndpoint] = []

            def _on_connection(protocol: Any) -> None:
                if not first_conn.done():
                    first_conn.set_result(protocol)

            log.info("waiting for the peer's QUIC connection…")
            raw_sock = sock.into_raw()
            sock = None
            endpoint = await quic.attach_server(
                raw_sock,
                quic.build_server_config(cert_der, key),
                on_connection=_on_connection,
                server_endpoints=endpoints,
            )
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(asyncio.shield(first_conn), QUIC_HANDSHAKE_TIMEOUT_SECS)
            if not first_conn.done():
                raise QuicError(
                    f"QUIC handshake with {stun.fmt_addr(peer)} timed out after "
                    f"{int(QUIC_HANDSHAKE_TIMEOUT_SECS)}s"
                )
            protocol = first_conn.result()
        else:
            log.info("initiating QUIC connection to peer…")
            raw_sock = sock.into_raw()
            sock = None
            protocol = await quic.attach_client(raw_sock, quic.build_client_config())
            endpoint = protocol
            await quic.connect(protocol, peer, timeout=QUIC_HANDSHAKE_TIMEOUT_SECS)
            peer_fp = quic.peer_certificate_fingerprint(protocol)
            if peer_fp is not None:
                log.info("peer certificate fingerprint: %s (share out-of-band)", peer_fp)

        # ── T6 — the tunnel bridge, until clean close ──
        if cfg.keep_alive_interval_secs > 0:
            keep_alive = quic.start_keep_alive(protocol, float(cfg.keep_alive_interval_secs))
        if role is Role.SERVER:
            await tunnel.run_server_side(endpoints[0], setup.target)
        else:
            await tunnel.run_client_side(protocol, setup.local_port)
        log.info("tunnel closed; goodbye")
    finally:
        if keep_alive is not None:
            keep_alive.cancel()
            with contextlib.suppress(BaseException):
                await keep_alive
        if endpoint is not None:
            quic.close_endpoint(endpoint)  # the transport owns the socket from T5 on
        elif raw_sock is not None:
            with contextlib.suppress(OSError):
                raw_sock.close()
        elif sock is not None:
            with contextlib.suppress(Exception):
                await sock.close()
        if channel is not None:
            channel.close()


# ---------------------------------------------------------------------------
# main(): S0 + exit codes (Rust main.rs: `error:` block + hint, exit 1)
# ---------------------------------------------------------------------------


def _bail(exc: PromptBail) -> PromptBail:
    """Give the bare bail classes the Rust user-facing messages."""
    if isinstance(exc, Eof):
        return Eof("stdin closed before a peer address was entered")
    return Aborted("aborted by the user")


def _fail(error: BaseException) -> int:
    """Print the Rust-style ``error:`` block (blank line, the message chain,
    an optional hint) and return the exit code."""
    print(file=sys.stderr)
    print(f"error: {format_error(error)}", file=sys.stderr)
    hint = hint_for(error)
    if hint is not None:
        print(hint, file=sys.stderr)
    return 1


def main(argv: list[str] | None = None) -> int:
    """CLI entry point (Phase 10: one §2 attempt). Returns the exit code."""
    cli = Cli.parse(argv)
    setup_logging(cli.verbose)
    if cli.tui:
        log.warning("--tui: the TUI lands in Phase 12; using plain log output")
    try:
        cfg = Config.load(cli.config)
    except ConfigError as e:
        return _fail(e)
    log.info("loaded config: %s", cli.config)
    log.debug(
        "config: stun_servers=%s punch_interval_ms=%d punch_timeout_secs=%d "
        "keep_alive_interval_secs=%d local_tcp_listen_port=%r remote_target_addr=%r "
        "telegram=%s",
        cfg.stun_servers,
        cfg.punch_interval_ms,
        cfg.punch_timeout_secs,
        cfg.keep_alive_interval_secs,
        cfg.local_tcp_listen_port,
        cfg.remote_target_addr,
        "configured" if cfg.telegram is not None else "absent",
    )
    try:
        mode = resolve_exchange_mode(cli, cfg)
    except ExchangeModeError as e:
        return _fail(e)
    interactive = _stdin_interactive()
    try:
        asyncio.run(run_attempt(cfg, mode, read=read_line_stdin, interactive=interactive))
    except KeyboardInterrupt:
        return _fail(Aborted("aborted by the user"))
    except PromptBail as e:
        return _fail(_bail(e))
    except Exception as e:
        return _fail(e)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
