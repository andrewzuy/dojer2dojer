use anyhow::Context;
use serde::Deserialize;
use std::path::Path;

/// Tool configuration, loaded from TOML.
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// STUN servers to try, in order, e.g. `"stun.l.google.com:19302"`.
    pub stun_servers: Vec<String>,
    /// Interval between outbound punch packets, in milliseconds.
    #[serde(default = "default_punch_interval_ms")]
    pub punch_interval_ms: u64,
    /// How long to keep trying to hole-punch before giving up, in seconds.
    #[serde(default = "default_punch_timeout_secs")]
    pub punch_timeout_secs: u64,
    /// How often (in seconds) to send a QUIC keep-alive PING while the tunnel
    /// is idle, so NAT port mappings don't expire and drop the connection.
    /// `0` disables keep-alive.
    #[serde(default = "default_keep_alive_interval_secs")]
    pub keep_alive_interval_secs: u64,
    /// Local TCP port to listen on (the "client side" of the tunnel).
    pub local_tcp_listen_port: Option<u16>,
    /// Where to forward incoming tunneled TCP (the "server side" of the tunnel).
    pub remote_target_addr: Option<String>,
    /// Optional Telegram bot-to-bot signaling (the `[telegram]` table).
    /// Presence alone does not activate it — the `--telegram` CLI flag does.
    #[serde(default)]
    pub telegram: Option<TelegramConfig>,
}

/// Telegram bot-to-bot signaling settings (see `src/telegram.rs`).
///
/// Enables the second, automatic address-exchange channel: this machine's
/// bot and the peer's bot DM each other their public addresses, so nobody
/// has to copy/paste an address between terminals. Both bots need
/// Bot-to-Bot Communication Mode enabled in @BotFather.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct TelegramConfig {
    /// This bot's API token from @BotFather (`123456:ABC-DEF...`).
    pub token: String,
    /// The *peer's* bot's numeric user id (what `getMe.id` / `/id@BotFather`
    /// prints). Private bot-to-bot messages are sent to this id as `chat_id`.
    pub peer_bot_id: i64,
    /// How long (seconds) to wait for the peer bot's address before falling
    /// back to the manual "type the address" prompt.
    #[serde(default = "default_telegram_timeout_secs")]
    pub timeout_secs: u64,
}

fn default_telegram_timeout_secs() -> u64 {
    120
}

fn default_punch_interval_ms() -> u64 {
    500
}

fn default_punch_timeout_secs() -> u64 {
    30
}

fn default_keep_alive_interval_secs() -> u64 {
    5
}

impl Config {
    /// Load and parse the config file at `path`.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config file {}", path.display()))?;
        let cfg: Config = toml::from_str(&text)
            .with_context(|| format!("parsing config file {}", path.display()))?;
        if cfg.stun_servers.is_empty() {
            anyhow::bail!("config: `stun_servers` must contain at least one server");
        }
        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_full_config() {
        let dir = std::env::temp_dir();
        let path = dir.join("p2p-tunnel-test-config.toml");
        std::fs::write(
            &path,
            r#"
stun_servers = ["stun.l.google.com:19302"]
local_tcp_listen_port = 12345
remote_target_addr = "127.0.0.1:8080"
"#,
        )
        .unwrap();
        let cfg = Config::load(&path).unwrap();
        assert_eq!(cfg.stun_servers, vec!["stun.l.google.com:19302"]);
        assert_eq!(cfg.punch_interval_ms, 500); // default
        assert_eq!(cfg.punch_timeout_secs, 30); // default
        assert_eq!(cfg.keep_alive_interval_secs, 5); // default
        assert_eq!(cfg.local_tcp_listen_port, Some(12345));
        assert_eq!(cfg.remote_target_addr.as_deref(), Some("127.0.0.1:8080"));
        assert_eq!(cfg.telegram, None); // absent table → None
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn loads_telegram_section() {
        let dir = std::env::temp_dir();
        let path = dir.join("p2p-tunnel-test-config-tg.toml");
        std::fs::write(
            &path,
            r#"
stun_servers = ["stun.l.google.com:19302"]

[telegram]
token = "123456:ABC-DEF"
peer_bot_id = 987654321
"#,
        )
        .unwrap();
        let cfg = Config::load(&path).unwrap();
        let tg = cfg.telegram.expect("[telegram] table present");
        assert_eq!(tg.token, "123456:ABC-DEF");
        assert_eq!(tg.peer_bot_id, 987654321);
        assert_eq!(tg.timeout_secs, 120); // default
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn telegram_timeout_override() {
        let dir = std::env::temp_dir();
        let path = dir.join("p2p-tunnel-test-config-tg2.toml");
        std::fs::write(
            &path,
            r#"
stun_servers = ["stun.l.google.com:19302"]

[telegram]
token = "t"
peer_bot_id = 1
timeout_secs = 5
"#,
        )
        .unwrap();
        let cfg = Config::load(&path).unwrap();
        assert_eq!(cfg.telegram.unwrap().timeout_secs, 5);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn explicit_overrides_win() {
        let dir = std::env::temp_dir();
        let path = dir.join("p2p-tunnel-test-config2.toml");
        std::fs::write(
            &path,
            r#"
stun_servers = ["a:1", "b:2"]
punch_interval_ms = 250
punch_timeout_secs = 5
keep_alive_interval_secs = 0
"#,
        )
        .unwrap();
        let cfg = Config::load(&path).unwrap();
        assert_eq!(cfg.punch_interval_ms, 250);
        assert_eq!(cfg.punch_timeout_secs, 5);
        assert_eq!(cfg.keep_alive_interval_secs, 0); // explicit override
        assert_eq!(cfg.local_tcp_listen_port, None);
        assert_eq!(cfg.remote_target_addr, None);
        let _ = std::fs::remove_file(&path);
    }
}
