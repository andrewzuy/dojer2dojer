"""Tests for :mod:`p2p_tunnel.cli` (ported from the Rust ``cli.rs`` tests,
plus prompt-loop behavior tests required by PLAN.md Phase 1)."""

from __future__ import annotations

import io
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout

from p2p_tunnel.cli import (
    Aborted,
    Cli,
    Eof,
    ExchangeMode,
    ExchangeModeError,
    ModeToggled,
    PeerAddrError,
    PromptBail,
    PromptOutcome,
    Setup,
    parse_peer_addr,
    prompt_local_port,
    prompt_peer_addr,
    prompt_role,
    prompt_server_target,
    read_line_stdin,
    resolve_exchange_mode,
    resolve_setup,
)
from p2p_tunnel.config import Config, ConfigError
from p2p_tunnel.role import Role


class ParsePeerAddrTests(unittest.TestCase):
    def test_parses_valid_addrs(self):
        self.assertEqual(parse_peer_addr("1.2.3.4:1234"), ("1.2.3.4", 1234))
        self.assertEqual(parse_peer_addr(" [2001:db8::1]:443 "), ("2001:db8::1", 443))
        self.assertEqual(parse_peer_addr("127.0.0.1:65535"), ("127.0.0.1", 65535))

    def test_rejects_invalid_addrs(self):
        for bad in ("not-an-addr", "1.2.3.4", "", "   ", "1.2.3.4:0", "1.2.3.4:99999",
                    "1.2.3.4:abc", "1.2.3.4:", "[2001:db8::1]", "a.b.c.d:1"):
            with self.assertRaises(PeerAddrError, msg=f"should reject {bad!r}"):
                parse_peer_addr(bad)


class PromptPeerAddrTests(unittest.TestCase):
    def run_prompt(self, outcomes, read_err: type[BaseException] | None = None):
        """Feed a sequence of PromptOutcomes through prompt_peer_addr."""
        it = iter(outcomes)

        def read() -> PromptOutcome:
            if read_err is not None:
                raise read_err("boom")
            return next(it)

        return prompt_peer_addr(read)

    def test_accepts_first_valid_line(self):
        out = self.run_prompt([PromptOutcome.from_line("  9.9.9.9:443  ")])
        self.assertEqual(out, ("9.9.9.9", 443))

    def test_reprompts_on_empty_and_invalid(self):
        out = self.run_prompt(
            [
                PromptOutcome.from_line(""),
                PromptOutcome.from_line("garbage"),
                PromptOutcome.from_line("1.1.1.1:53"),
            ]
        )
        self.assertEqual(out, ("1.1.1.1", 53))

    def test_reprompt_errors_are_printed(self):
        err = io.StringIO()
        with redirect_stderr(err):
            self.run_prompt(
                [PromptOutcome.from_line(""), PromptOutcome.from_line("1.1.1.1:53")]
            )
        text = err.getvalue()
        self.assertIn("Address cannot be empty, please try again.", text)

    def test_invalid_address_message_includes_line(self):
        err = io.StringIO()
        with redirect_stderr(err):
            self.run_prompt(
                [PromptOutcome.from_line("nope"), PromptOutcome.from_line("1.1.1.1:53")]
            )
        self.assertIn("Invalid address 'nope'", err.getvalue())

    def test_mode_toggled_bails(self):
        # A toggle on the first read bails immediately.
        with self.assertRaises(ModeToggled):
            self.run_prompt([PromptOutcome.mode_toggled_outcome()])
        # A toggle mid-prompt (after an invalid line) also bails.
        with self.assertRaises(ModeToggled):
            self.run_prompt(
                [PromptOutcome.from_line("bad"), PromptOutcome.mode_toggled_outcome()]
            )

    def test_aborted_bails(self):
        with self.assertRaises(Aborted):
            self.run_prompt([PromptOutcome.aborted_outcome()])

    def test_eof_bails(self):
        with self.assertRaises(Eof):
            self.run_prompt([PromptOutcome.eof_outcome()])

    def test_io_error_maps_to_aborted(self):
        with self.assertRaises(Aborted):
            self.run_prompt([], read_err=OSError)

    def test_all_bails_are_prompt_bails(self):
        for exc in (ModeToggled, Aborted, Eof):
            self.assertTrue(issubclass(exc, PromptBail))


class CliParseTests(unittest.TestCase):
    def test_defaults(self):
        cli = Cli.parse([])
        self.assertEqual(str(cli.config), "config.toml")
        self.assertFalse(cli.verbose)
        self.assertFalse(cli.telegram)
        self.assertFalse(cli.manual)
        self.assertFalse(cli.tui)
        self.assertFalse(cli.no_tui)

    def test_all_flags(self):
        cli = Cli.parse(
            ["--config", "/x/c.toml", "--verbose", "--telegram", "--tui"]
        )
        self.assertEqual(str(cli.config), "/x/c.toml")
        self.assertTrue(cli.verbose)
        self.assertTrue(cli.telegram)
        self.assertTrue(cli.tui)
        self.assertFalse(cli.no_tui)

    def test_no_tui_flag(self):
        self.assertTrue(Cli.parse(["--no-tui"]).no_tui)

    def test_manual_flag(self):
        self.assertTrue(Cli.parse(["--manual"]).manual)

    def test_no_telegram_alias(self):
        # `--no-telegram` is an alias for `--manual` (v2 CLI table).
        cli = Cli.parse(["--no-telegram"])
        self.assertTrue(cli.manual)
        self.assertFalse(cli.telegram)


class ResolveExchangeModeTests(unittest.TestCase):
    """The D2 mode-resolution matrix (pure function, PLAN §5.7)."""

    def cfg(self, telegram: bool) -> Config:
        tg = None
        if telegram:
            from p2p_tunnel.config import TelegramConfig

            tg = TelegramConfig(token="1:ABC", peer_bot_id=42, secret="s")
        return Config(stun_servers=["stun.l.google.com:19302"], telegram=tg)

    def test_default_is_telegram_when_configured(self):
        self.assertEqual(
            resolve_exchange_mode(Cli.parse([]), self.cfg(telegram=True)),
            ExchangeMode.TELEGRAM,
        )

    def test_default_is_manual_when_not_configured(self):
        self.assertEqual(
            resolve_exchange_mode(Cli.parse([]), self.cfg(telegram=False)),
            ExchangeMode.MANUAL,
        )

    def test_manual_forces_manual_with_table(self):
        self.assertEqual(
            resolve_exchange_mode(Cli.parse(["--manual"]), self.cfg(telegram=True)),
            ExchangeMode.MANUAL,
        )

    def test_manual_forces_manual_without_table(self):
        self.assertEqual(
            resolve_exchange_mode(Cli.parse(["--manual"]), self.cfg(telegram=False)),
            ExchangeMode.MANUAL,
        )

    def test_no_telegram_alias_forces_manual(self):
        self.assertEqual(
            resolve_exchange_mode(
                Cli.parse(["--no-telegram"]), self.cfg(telegram=True)
            ),
            ExchangeMode.MANUAL,
        )

    def test_telegram_forces_telegram_with_table(self):
        self.assertEqual(
            resolve_exchange_mode(Cli.parse(["--telegram"]), self.cfg(telegram=True)),
            ExchangeMode.TELEGRAM,
        )

    def test_telegram_without_table_is_error_with_hint(self):
        with self.assertRaises(ExchangeModeError) as ctx:
            resolve_exchange_mode(Cli.parse(["--telegram"]), self.cfg(telegram=False))
        msg = str(ctx.exception)
        self.assertIn("[telegram]", msg)
        self.assertIn("--telegram", msg)


class PromptRoleTests(unittest.TestCase):
    def run_prompt(self, outcomes, read_err: type[BaseException] | None = None):
        it = iter(outcomes)

        def read() -> PromptOutcome:
            if read_err is not None:
                raise read_err("boom")
            return next(it)

        return prompt_role(read)

    def test_empty_line_takes_default_client(self):
        self.assertIs(self.run_prompt([PromptOutcome.from_line("")]), Role.CLIENT)

    def test_accepts_client_spellings(self):
        for line in ("client", "c", "Client", "  CLIENT  "):
            self.assertIs(
                self.run_prompt([PromptOutcome.from_line(line)]),
                Role.CLIENT,
                msg=line,
            )

    def test_accepts_server_spellings(self):
        for line in ("server", "s", "Server", "  SERVER  "):
            self.assertIs(
                self.run_prompt([PromptOutcome.from_line(line)]),
                Role.SERVER,
                msg=line,
            )

    def test_reprompts_on_invalid_then_accepts(self):
        out = self.run_prompt(
            [
                PromptOutcome.from_line("boss"),
                PromptOutcome.from_line(""),
            ]
        )
        self.assertIs(out, Role.CLIENT)

    def test_invalid_role_message(self):
        err = io.StringIO()
        with redirect_stderr(err):
            self.run_prompt(
                [PromptOutcome.from_line("boss"), PromptOutcome.from_line("s")]
            )
        self.assertIn("Invalid role 'boss'", err.getvalue())

    def test_mode_toggled_bails(self):
        with self.assertRaises(ModeToggled):
            self.run_prompt([PromptOutcome.mode_toggled_outcome()])

    def test_aborted_bails(self):
        with self.assertRaises(Aborted):
            self.run_prompt([PromptOutcome.aborted_outcome()])

    def test_eof_bails(self):
        with self.assertRaises(Eof):
            self.run_prompt([PromptOutcome.eof_outcome()])

    def test_io_error_maps_to_aborted(self):
        with self.assertRaises(Aborted):
            self.run_prompt([], read_err=OSError)


class PromptLocalPortTests(unittest.TestCase):
    def run_prompt(self, outcomes, prefilled):
        it = iter(outcomes)

        def read() -> PromptOutcome:
            return next(it)

        return prompt_local_port(read, prefilled)

    def test_explicit_port(self):
        self.assertEqual(self.run_prompt([PromptOutcome.from_line("8080")], None), 8080)

    def test_empty_takes_prefill(self):
        self.assertEqual(
            self.run_prompt([PromptOutcome.from_line("")], 12345), 12345
        )

    def test_explicit_wins_over_prefill(self):
        self.assertEqual(
            self.run_prompt([PromptOutcome.from_line("9999")], 12345), 9999
        )

    def test_empty_without_prefill_reprompts(self):
        out = self.run_prompt(
            [PromptOutcome.from_line(""), PromptOutcome.from_line("7000")], None
        )
        self.assertEqual(out, 7000)

    def test_rejects_out_of_range_and_garbage(self):
        out = self.run_prompt(
            [
                PromptOutcome.from_line("0"),
                PromptOutcome.from_line("65536"),
                PromptOutcome.from_line("99999"),
                PromptOutcome.from_line("abc"),
                PromptOutcome.from_line("-1"),
                PromptOutcome.from_line("4242"),
            ],
            None,
        )
        self.assertEqual(out, 4242)

    def test_invalid_port_message(self):
        err = io.StringIO()
        with redirect_stderr(err), self.assertRaises(Eof):
            # the prompt reprompts after the invalid line; feed EOF to stop
            self.run_prompt(
                [
                    PromptOutcome.from_line("70000"),
                    PromptOutcome.eof_outcome(),
                ],
                None,
            )
        self.assertIn("Invalid port '70000'", err.getvalue())

    def test_mode_toggled_bails(self):
        with self.assertRaises(ModeToggled):
            self.run_prompt([PromptOutcome.mode_toggled_outcome()], None)

    def test_aborted_bails(self):
        with self.assertRaises(Aborted):
            self.run_prompt([PromptOutcome.aborted_outcome()], None)

    def test_eof_bails(self):
        with self.assertRaises(Eof):
            self.run_prompt([PromptOutcome.eof_outcome()], None)


class PromptServerTargetTests(unittest.TestCase):
    def run_prompt(self, outcomes, prefilled):
        it = iter(outcomes)

        def read() -> PromptOutcome:
            return next(it)

        return prompt_server_target(read, prefilled)

    def test_explicit_addr(self):
        self.assertEqual(
            self.run_prompt([PromptOutcome.from_line("192.168.1.10:22")], None),
            ("192.168.1.10", 22),
        )

    def test_explicit_ipv6(self):
        self.assertEqual(
            self.run_prompt([PromptOutcome.from_line("[::1]:8080")], None),
            ("::1", 8080),
        )

    def test_empty_takes_prefill(self):
        self.assertEqual(
            self.run_prompt([PromptOutcome.from_line("")], "10.0.0.5:3000"),
            ("10.0.0.5", 3000),
        )

    def test_empty_without_prefill_reprompts(self):
        out = self.run_prompt(
            [PromptOutcome.from_line(""), PromptOutcome.from_line("1.2.3.4:9")], None
        )
        self.assertEqual(out, ("1.2.3.4", 9))

    def test_invalid_prefill_reprompts(self):
        out = self.run_prompt(
            [
                PromptOutcome.from_line(""),  # takes the invalid prefill → reprompt
                PromptOutcome.from_line("5.6.7.8:1"),
            ],
            "not-an-addr",
        )
        self.assertEqual(out, ("5.6.7.8", 1))

    def test_reprompts_on_invalid_input(self):
        out = self.run_prompt(
            [PromptOutcome.from_line("nope"), PromptOutcome.from_line("1.1.1.1:53")],
            None,
        )
        self.assertEqual(out, ("1.1.1.1", 53))

    def test_invalid_address_message(self):
        err = io.StringIO()
        with redirect_stderr(err), self.assertRaises(Eof):
            self.run_prompt(
                [PromptOutcome.from_line("nope"), PromptOutcome.eof_outcome()], None
            )
        self.assertIn("Invalid address 'nope'", err.getvalue())

    def test_mode_toggled_bails(self):
        with self.assertRaises(ModeToggled):
            self.run_prompt([PromptOutcome.mode_toggled_outcome()], None)

    def test_eof_bails(self):
        with self.assertRaises(Eof):
            self.run_prompt([PromptOutcome.eof_outcome()], None)


class ResolveSetupTests(unittest.TestCase):
    def cfg(self, **kw) -> Config:
        base = dict(stun_servers=["stun.l.google.com:19302"])
        base.update(kw)
        return Config(**base)

    def lines(self, *ls: str):
        it = iter(ls)

        def read() -> PromptOutcome:
            return PromptOutcome.from_line(next(it))

        return read

    def test_interactive_client_prefilled_accepts_default(self):
        out = resolve_setup(
            self.cfg(local_tcp_listen_port=12345), self.lines("", ""), interactive=True
        )
        self.assertEqual(out, Setup(role=Role.CLIENT, local_port=12345))

    def test_interactive_server_prefilled_accepts_default(self):
        out = resolve_setup(
            self.cfg(remote_target_addr="10.0.0.9:8080"),
            self.lines("server", ""),
            interactive=True,
        )
        self.assertEqual(out, Setup(role=Role.SERVER, target=("10.0.0.9", 8080)))

    def test_interactive_client_no_prefill_prompts(self):
        out = resolve_setup(
            self.cfg(), self.lines("client", "4242"), interactive=True
        )
        self.assertEqual(out, Setup(role=Role.CLIENT, local_port=4242))

    def test_interactive_server_no_prefill_prompts(self):
        out = resolve_setup(
            self.cfg(local_tcp_listen_port=1),
            self.lines("s", "192.168.0.2:22"),
            interactive=True,
        )
        self.assertEqual(out, Setup(role=Role.SERVER, target=("192.168.0.2", 22)))

    def test_interactive_role_conflict_reraises_bail(self):
        # A mode toggle during the role prompt propagates as PromptBail.
        with self.assertRaises(ModeToggled):
            resolve_setup(
                self.cfg(),
                lambda: PromptOutcome.mode_toggled_outcome(),
                interactive=True,
            )

    def test_noninteractive_client_key_infers_client(self):
        out = resolve_setup(
            self.cfg(local_tcp_listen_port=5555),
            None,
            interactive=False,
        )
        self.assertEqual(out, Setup(role=Role.CLIENT, local_port=5555))

    def test_noninteractive_server_key_infers_server(self):
        out = resolve_setup(
            self.cfg(remote_target_addr="172.16.0.4:3306"),
            None,
            interactive=False,
        )
        self.assertEqual(out, Setup(role=Role.SERVER, target=("172.16.0.4", 3306)))

    def test_noninteractive_both_keys_is_ambiguous_error(self):
        with self.assertRaises(ConfigError) as ctx:
            resolve_setup(
                self.cfg(local_tcp_listen_port=1, remote_target_addr="1.2.3.4:5"),
                None,
                interactive=False,
            )
        self.assertIn("cannot determine the role", str(ctx.exception))

    def test_noninteractive_neither_key_is_error(self):
        with self.assertRaises(ConfigError) as ctx:
            resolve_setup(self.cfg(), None, interactive=False)
        self.assertIn("cannot determine the role", str(ctx.exception))

    def test_noninteractive_invalid_server_target_is_error(self):
        with self.assertRaises(ConfigError) as ctx:
            resolve_setup(
                self.cfg(remote_target_addr="nope"), None, interactive=False
            )
        self.assertIn("remote_target_addr", str(ctx.exception))


class StdinTransportTests(unittest.TestCase):
    def test_read_line_stdin_line(self):
        old = sys.stdin
        sys.stdin = io.StringIO("hello\n")
        try:
            out = read_line_stdin("p> ")
        finally:
            sys.stdin = old
        self.assertEqual(out, PromptOutcome.from_line("hello\n"))

    def test_read_line_stdin_eof(self):
        old = sys.stdin
        sys.stdin = io.StringIO("")
        try:
            out = read_line_stdin("p> ")
        finally:
            sys.stdin = old
        self.assertTrue(out.eof)


if __name__ == "__main__":
    unittest.main()


if __name__ == "__main__":
    unittest.main()
