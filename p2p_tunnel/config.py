"""Tool configuration, loaded from TOML (port of the Rust ``src/config.rs``).

Uses the stdlib :mod:`tomllib` (read-only TOML). Same keys, defaults, and
validation as the Rust version:

* ``stun_servers`` — required, at least one entry (``host`` or ``host:port``).
* ``punch_interval_ms`` — default 500 (floor 10 applied at use site).
* ``punch_timeout_secs`` — default 30.
* ``keep_alive_interval_secs`` — default 5; ``0`` disables keep-alive.
* ``local_tcp_listen_port`` — optional; required for the client role.
* ``remote_target_addr`` — optional; required for the server role.
* ``[telegram]`` — optional table (token, peer_bot_id, timeout_secs, secret);
  presence alone does not activate it — the ``--telegram`` CLI flag does.

Unknown keys are ignored (serde default behavior in the Rust version).
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path

DEFAULT_PUNCH_INTERVAL_MS = 500
DEFAULT_PUNCH_TIMEOUT_SECS = 30
DEFAULT_KEEP_ALIVE_INTERVAL_SECS = 5
DEFAULT_TELEGRAM_TIMEOUT_SECS = 120


class ConfigError(Exception):
    """The config file is missing, unreadable, malformed, or invalid."""


@dataclass
class TelegramConfig:
    """Telegram bot-to-bot signaling settings (see :mod:`p2p_tunnel.telegram`).

    Enables the second, automatic address-exchange channel: this machine's
    bot and the peer's bot DM each other their public addresses, so nobody
    has to copy/paste an address between terminals. Both bots need
    Bot-to-Bot Communication Mode enabled in @BotFather.
    """

    #: This bot's API token from @BotFather (``123456:ABC-DEF...``).
    token: str
    #: The *peer's* bot's numeric user id (what ``getMe.id`` prints).
    peer_bot_id: int
    #: How long (seconds) to wait for the peer bot's address before falling
    #: back to the manual "type the address" prompt.
    timeout_secs: int = DEFAULT_TELEGRAM_TIMEOUT_SECS
    #: A small shared secret both operators must paste into their configs.
    #: It travels in the ``PTUN READY`` line the bots exchange *before* STUN.
    secret: str | None = None


@dataclass
class Config:
    """The loaded tool configuration."""

    #: STUN servers to try, in order, e.g. ``"stun.l.google.com:19302"``.
    stun_servers: list[str]
    #: Interval between outbound punch packets, in milliseconds.
    punch_interval_ms: int = DEFAULT_PUNCH_INTERVAL_MS
    #: How long to keep trying to hole-punch before giving up, in seconds.
    punch_timeout_secs: int = DEFAULT_PUNCH_TIMEOUT_SECS
    #: QUIC keep-alive PING interval in seconds while the tunnel is idle;
    #: ``0`` disables keep-alive.
    keep_alive_interval_secs: int = DEFAULT_KEEP_ALIVE_INTERVAL_SECS
    #: Local TCP port to listen on (the "client side" of the tunnel).
    local_tcp_listen_port: int | None = None
    #: Where to forward incoming tunneled TCP (the "server side"), ``ip:port``.
    remote_target_addr: str | None = None
    #: Optional Telegram signaling (``None`` when the table is absent).
    telegram: TelegramConfig | None = None

    @classmethod
    def load(cls, path: str | Path) -> Config:
        """Load and parse the config file at ``path``."""
        p = Path(path)
        try:
            raw = p.read_bytes()
        except OSError as e:
            raise ConfigError(f"reading config file {p}: {e.strerror or e}") from e
        try:
            data = tomllib.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, tomllib.TOMLDecodeError) as e:
            raise ConfigError(f"parsing config file {p}: {e}") from e

        stun_servers = data.get("stun_servers", [])
        if not isinstance(stun_servers, list) or not all(
            isinstance(s, str) for s in stun_servers
        ):
            raise ConfigError(
                f"parsing config file {p}: `stun_servers` must be a list of strings"
            )
        if not stun_servers:
            raise ConfigError("config: `stun_servers` must contain at least one server")

        def _int(key: str, default: int) -> int:
            value = data.get(key, default)
            if isinstance(value, bool) or not isinstance(value, int):
                raise ConfigError(
                    f"parsing config file {p}: `{key}` must be an integer"
                )
            return value

        local_tcp_listen_port = data.get("local_tcp_listen_port")
        if local_tcp_listen_port is not None:
            if (
                isinstance(local_tcp_listen_port, bool)
                or not isinstance(local_tcp_listen_port, int)
                or not 0 < local_tcp_listen_port < 65536
            ):
                raise ConfigError(
                    f"parsing config file {p}: `local_tcp_listen_port` must be a port number"
                )

        remote_target_addr = data.get("remote_target_addr")
        if remote_target_addr is not None and not isinstance(
            remote_target_addr, str
        ):
            raise ConfigError(
                f"parsing config file {p}: `remote_target_addr` must be a string"
            )

        telegram: TelegramConfig | None = None
        if "telegram" in data:
            tg = data["telegram"]
            if not isinstance(tg, dict):
                raise ConfigError(f"parsing config file {p}: `[telegram]` must be a table")
            token = tg.get("token")
            peer_bot_id = tg.get("peer_bot_id")
            if not isinstance(token, str) or not token:
                raise ConfigError(
                    f"parsing config file {p}: `[telegram] token` is required"
                )
            if isinstance(peer_bot_id, bool) or not isinstance(peer_bot_id, int):
                raise ConfigError(
                    f"parsing config file {p}: `[telegram] peer_bot_id` must be an integer"
                )
            secret = tg.get("secret")
            if secret is not None and not isinstance(secret, str):
                raise ConfigError(
                    f"parsing config file {p}: `[telegram] secret` must be a string"
                )
            timeout_secs = DEFAULT_TELEGRAM_TIMEOUT_SECS
            if "timeout_secs" in tg:
                timeout_secs = tg["timeout_secs"]
                if (
                    isinstance(timeout_secs, bool)
                    or not isinstance(timeout_secs, int)
                ):
                    raise ConfigError(
                        f"parsing config file {p}: `[telegram] timeout_secs` must be an integer"
                    )
            telegram = TelegramConfig(
                token=token,
                peer_bot_id=peer_bot_id,
                timeout_secs=timeout_secs,
                secret=secret,
            )

        return cls(
            stun_servers=list(stun_servers),
            punch_interval_ms=_int("punch_interval_ms", DEFAULT_PUNCH_INTERVAL_MS),
            punch_timeout_secs=_int("punch_timeout_secs", DEFAULT_PUNCH_TIMEOUT_SECS),
            keep_alive_interval_secs=_int(
                "keep_alive_interval_secs", DEFAULT_KEEP_ALIVE_INTERVAL_SECS
            ),
            local_tcp_listen_port=local_tcp_listen_port,
            remote_target_addr=remote_target_addr,
            telegram=telegram,
        )
