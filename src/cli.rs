use clap::Parser;
use std::net::SocketAddr;
use std::path::PathBuf;

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
    /// Use the Telegram bot-to-bot signaling channel to exchange public
    /// addresses automatically (requires the `[telegram]` config table and
    /// Bot-to-Bot Communication Mode enabled for both bots in @BotFather).
    /// Falls back to the manual address prompt if the peer bot is not reached
    /// within the timeout.
    #[arg(long)]
    pub telegram: bool,
    /// Show the live terminal UI (auto-enabled when attached to a TTY).
    #[arg(long)]
    pub tui: bool,
    /// Force the plain log output, even when attached to a TTY.
    #[arg(long)]
    pub no_tui: bool,
}

/// Read the peer's public address from the user, re-prompting until valid.
///
/// `read` is a closure that returns the next line of user input (`None` on
/// EOF). Injecting it keeps this function pure and testable; the caller
/// (`main.rs`) supplies either a plain `stdin` read or the TUI's inline
/// prompt (which temporarily leaves raw mode so the terminal's line
/// discipline works).
///
/// One-shot interactive prompt: briefly blocking the async runtime on input
/// is acceptable here (the pipeline is otherwise idle waiting for this).
pub fn prompt_peer_addr(
    read: &mut dyn FnMut() -> std::io::Result<Option<String>>,
) -> anyhow::Result<SocketAddr> {
    loop {
        let Some(line) = read()? else {
            anyhow::bail!("no input received (stdin closed)");
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

#[cfg(test)]
mod tests {
    use super::*;

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
