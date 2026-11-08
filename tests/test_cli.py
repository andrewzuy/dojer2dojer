"""Tests for :mod:`p2p_tunnel.cli` (ported from the Rust ``cli.rs`` tests,
plus prompt-loop behavior tests required by PLAN.md Phase 1)."""

from __future__ import annotations

import io
import unittest
from contextlib import redirect_stderr, redirect_stdout

from p2p_tunnel.cli import (
    Aborted,
    Cli,
    Eof,
    ModeToggled,
    PeerAddrError,
    PromptBail,
    PromptOutcome,
    parse_peer_addr,
    prompt_peer_addr,
)


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


if __name__ == "__main__":
    unittest.main()
