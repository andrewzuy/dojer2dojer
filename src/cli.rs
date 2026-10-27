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
}

/// Prompt on stdin for the peer's public address until valid input arrives.
///
/// One-shot interactive prompt: briefly blocking the async runtime on stdin is
/// acceptable here (the main thread is otherwise idle waiting for input).
pub fn prompt_peer_addr() -> anyhow::Result<SocketAddr> {
    use std::io::Write;
    loop {
        print!("Enter peer's public address (ip:port): ");
        std::io::stdout().flush()?;
        let mut line = String::new();
        let n = std::io::stdin().read_line(&mut line)?;
        if n == 0 {
            anyhow::bail!("no input received (stdin closed)");
        }
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
        assert_eq!(parse_peer_addr("1.2.3.4:1234").unwrap(), "1.2.3.4:1234".parse().unwrap());
        assert_eq!(parse_peer_addr(" [2001:db8::1]:443 ").unwrap(), "[2001:db8::1]:443".parse().unwrap());
    }

    #[test]
    fn rejects_invalid_addrs() {
        assert!(parse_peer_addr("not-an-addr").is_err());
        assert!(parse_peer_addr("1.2.3.4").is_err()); // missing port
        assert!(parse_peer_addr("").is_err());
    }
}
