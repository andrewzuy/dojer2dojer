use clap::Parser;
use std::net::SocketAddr;
use std::path::PathBuf;

use crate::config::Config;
use crate::tui;
use crate::tui_state::ExchangeMode;

/// P2P NAT-traversal tunnel over QUIC.
#[derive(Debug, Parser)]
#[command(name = "p2p-tunnel", version, about)]
pub struct Cli {
    /// Path to the TOML config file.
    #[arg(long, default_value = "./config.toml")]
    pub config: PathBuf,
    /// Enable debug logging (RUST_LOG takes precedence if set).
    #[arg(long)]
    pub verbose: bool,
    /// Force Telegram address-exchange mode: the bots DM each other's public
    /// addresses automatically (requires a usable `[telegram]` config table
    /// and Bot-to-Bot Communication Mode enabled for both bots in @BotFather).
    /// Since v2, Telegram is the *default* when a usable table is configured
    /// (see `--manual`); this flag only errors early on a missing table.
    /// With the TUI you can switch back and forth with the `t` key at any
    /// time; if the peer is not reached within the timeout the manual address
    /// prompt is offered.
    #[arg(long)]
    pub telegram: bool,
    /// Force the manual "type the peer address" prompt (alias: `--no-telegram`).
    /// Since v2, Telegram is the default exchange when a usable `[telegram]`
    /// table is configured; this flag opts out of that default.
    #[arg(long, visible_alias = "no-telegram")]
    pub manual: bool,
    /// This machine's role: `client` (listen on 127.0.0.1 and forward to the
    /// peer's service) or `server` (expose the local service to the peer).
    /// Can also be set as `role` in the config file (the flag wins). When
    /// neither is given, the role is selected interactively at startup.
    #[arg(long, value_name = "ROLE")]
    pub role: Option<String>,
    /// Show the live terminal UI (auto-enabled when attached to a TTY).
    #[arg(long)]
    pub tui: bool,
    /// Force the plain log output, even when attached to a TTY.
    #[arg(long)]
    pub no_tui: bool,
}

/// Why [`prompt_peer_addr`] stopped without producing an address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PromptBail {
    /// The user switched the address-exchange mode mid-prompt (the `t` key).
    ModeToggled,
    /// The user aborted the prompt (q / Esc / Ctrl-C).
    Aborted,
    /// stdin was closed (EOF).
    Eof,
}

/// Read the peer's public address from the user, re-prompting until valid.
///
/// `read` is a closure returning the next user-input outcome. Injecting it
/// keeps this function pure and testable; the caller (`main.rs`) supplies
/// either a plain `stdin` read or the TUI's inline prompt editor.
///
/// One-shot interactive prompt: briefly blocking the async runtime on input
/// is acceptable here (the pipeline is otherwise idle waiting for this).
pub fn prompt_peer_addr(
    read: &mut dyn FnMut() -> std::io::Result<tui::PromptOutcome>,
) -> Result<SocketAddr, PromptBail> {
    loop {
        let line = match read().map_err(|_| PromptBail::Aborted)? {
            tui::PromptOutcome::Line(line) => line,
            tui::PromptOutcome::ModeToggled => return Err(PromptBail::ModeToggled),
            tui::PromptOutcome::Aborted => return Err(PromptBail::Aborted),
            tui::PromptOutcome::Eof => return Err(PromptBail::Eof),
        };
        let line = line.trim();
        if line.is_empty() {
            eprintln!("Address cannot be empty, please try again.");
            continue;
        }
        match parse_peer_addr(line) {
            Ok(addr) => return Ok(addr),
            Err(e) => eprintln!("Invalid address '{line}': {e}. Please try again."),
        }
    }
}

/// Parse a "host:port" string into a SocketAddr with a helpful error.
pub fn parse_peer_addr(input: &str) -> Result<SocketAddr, String> {
    input
        .trim()
        .parse::<SocketAddr>()
        .map_err(|e| format!("{e:?}"))
}

/// Resolve the effective address-exchange mode (v2: Telegram first).
///
/// Precedence:
/// 1. explicit `--manual` / `--no-telegram` forces manual, no matter what;
/// 2. explicit `--telegram` requires a usable `[telegram]` table (token +
///    peer id + secret) and is a hard error otherwise;
/// 3. no flag: Telegram is the *default* when the table is usable, manual
///    otherwise.
///
/// Pure and unit-tested; the interactive `t` toggle in the TUI overrides the
/// result per-attempt at runtime.
pub fn resolve_exchange_mode(cli: &Cli, cfg: &Config) -> Result<ExchangeMode, String> {
    if cli.manual {
        return Ok(ExchangeMode::Manual);
    }
    let tg = cfg.telegram.as_ref();
    if cli.telegram {
        return match tg.filter(|t| t.is_complete()) {
            Some(_) => Ok(ExchangeMode::Telegram),
            None => Err(
                "--telegram: no usable `[telegram]` table in the config — it needs \
                 `token`, `peer_bot_id` and `secret` (see the sample config comments)"
                    .to_string(),
            ),
        };
    }
    if tg.is_some_and(|t| t.is_complete()) {
        Ok(ExchangeMode::Telegram) // v2 default: Telegram when configured
    } else {
        Ok(ExchangeMode::Manual)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TelegramConfig;

    fn cli_from(args: &[&str]) -> Cli {
        Cli::parse_from(args)
    }

    fn base_cfg() -> Config {
        Config {
            stun_servers: vec!["stun.l.google.com:19302".into()],
            punch_interval_ms: 500,
            punch_timeout_secs: 30,
            keep_alive_interval_secs: 5,
            local_tcp_listen_port: None,
            remote_target_addr: None,
            role: None,
            telegram: None,
        }
    }

    fn complete_table() -> TelegramConfig {
        TelegramConfig {
            token: "123:abc".into(),
            peer_bot_id: 987654321,
            timeout_secs: 120,
            secret: Some("my-secret".into()),
        }
    }

    // ── resolve_exchange_mode matrix ────────────────────────────────

    #[test]
    fn mode_defaults_to_manual_without_table() {
        let cli = cli_from(&["p2p-tunnel"]);
        let cfg = base_cfg();
        assert_eq!(
            resolve_exchange_mode(&cli, &cfg).unwrap(),
            ExchangeMode::Manual
        );
    }

    #[test]
    fn mode_defaults_to_telegram_with_complete_table() {
        let cli = cli_from(&["p2p-tunnel"]);
        let mut cfg = base_cfg();
        cfg.telegram = Some(complete_table());
        assert_eq!(
            resolve_exchange_mode(&cli, &cfg).unwrap(),
            ExchangeMode::Telegram
        );
    }

    #[test]
    fn mode_defaults_to_manual_with_incomplete_table() {
        let cli = cli_from(&["p2p-tunnel"]);
        let mut cfg = base_cfg();
        cfg.telegram = Some(TelegramConfig {
            secret: None, // missing the shared secret
            ..complete_table()
        });
        assert_eq!(
            resolve_exchange_mode(&cli, &cfg).unwrap(),
            ExchangeMode::Manual
        );
    }

    #[test]
    fn explicit_telegram_requires_table() {
        let cli = cli_from(&["p2p-tunnel", "--telegram"]);
        let cfg = base_cfg();
        let err = resolve_exchange_mode(&cli, &cfg).unwrap_err();
        assert!(err.contains("no usable"), "{err}");
        let mut cfg = base_cfg();
        cfg.telegram = Some(TelegramConfig {
            secret: None,
            ..complete_table()
        });
        assert!(resolve_exchange_mode(&cli, &cfg).is_err());
        cfg.telegram = Some(complete_table());
        assert_eq!(
            resolve_exchange_mode(&cli, &cfg).unwrap(),
            ExchangeMode::Telegram
        );
    }

    #[test]
    fn manual_flag_wins_over_table_and_telegram_flag() {
        let mut cfg = base_cfg();
        cfg.telegram = Some(complete_table());
        let cli = cli_from(&["p2p-tunnel", "--manual"]);
        assert_eq!(
            resolve_exchange_mode(&cli, &cfg).unwrap(),
            ExchangeMode::Manual
        );
        // Even alongside --telegram (explicit opt-out wins).
        let cli = cli_from(&["p2p-tunnel", "--manual", "--telegram"]);
        assert_eq!(
            resolve_exchange_mode(&cli, &cfg).unwrap(),
            ExchangeMode::Manual
        );
        // The visible alias works too.
        let cli = cli_from(&["p2p-tunnel", "--no-telegram"]);
        assert_eq!(
            resolve_exchange_mode(&cli, &cfg).unwrap(),
            ExchangeMode::Manual
        );
    }

    #[test]
    fn parses_valid_addrs() {
        assert_eq!(
            parse_peer_addr("1.2.3.4:1234").unwrap(),
            "1.2.3.4:1234".parse().unwrap()
        );
        assert_eq!(
            parse_peer_addr(" [2001:db8::1]:443 ").unwrap(),
            "[2001:db8::1]:443".parse().unwrap()
        );
    }

    #[test]
    fn rejects_invalid_addrs() {
        assert!(parse_peer_addr("not-an-addr").is_err());
        assert!(parse_peer_addr("1.2.3.4").is_err()); // missing port
        assert!(parse_peer_addr("").is_err());
    }
}
