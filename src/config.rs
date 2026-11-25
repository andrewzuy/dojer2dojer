use crate::role::Role;
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
    /// This machine's role: `"client"` or `"server"` (v2). Optional: when
    /// absent, the role is selected interactively at startup (the CLI
    /// `--role` flag wins over this key).
    #[serde(default)]
    pub role: Option<String>,
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
    /// A small shared secret both operators must paste into their configs.
    /// It travels in the `PTUN READY` line the bots exchange *before* STUN,
    /// which proves the other bot is up and listening (see
    /// `telegram::Telegram::handshake`). Required for the `--telegram` path.
    #[serde(default)]
    pub secret: Option<String>,
}

impl TelegramConfig {
    /// True when the table is usable for the Telegram exchange: a token, a
    /// peer bot id and the shared secret are all present. v2 defaults to
    /// Telegram only for complete tables (see `cli::resolve_exchange_mode`).
    pub fn is_complete(&self) -> bool {
        !self.token.trim().is_empty()
            && self.peer_bot_id > 0
            && self
                .secret
                .as_deref()
                .map(str::trim)
                .is_some_and(|s| !s.is_empty())
    }
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
        if let Some(r) = &cfg.role {
            Role::parse(r).ok_or_else(|| {
                anyhow::anyhow!("config: `role` must be \"client\" or \"server\" (got {r:?})")
            })?;
        }
        Ok(cfg)
    }

    /// The role declared in the config, if any (validated at load time).
    pub fn declared_role(&self) -> Option<Role> {
        self.role.as_deref().and_then(Role::parse)
    }

    /// Role-aware validation (v2): once the role is known, the role-specific
    /// key must be present (and valid). Called after role selection — from
    /// the CLI flag, the config, or the interactive setup prompt.
    pub fn validate_for_role(&self, role: Role) -> anyhow::Result<()> {
        match role {
            Role::Client => {
                self.local_tcp_listen_port.ok_or_else(|| {
                    anyhow::anyhow!(
                        "config: `local_tcp_listen_port` is required for the client role \n                     \
                         (the local TCP port to expose through the tunnel)"
                    )
                })?;
            }
            Role::Server => {
                let target = self.remote_target_addr.as_deref().ok_or_else(|| {
                    anyhow::anyhow!(
                        "config: `remote_target_addr` is required for the server role \n                     \
                         (the private ip:port to forward tunneled TCP to)"
                    )
                })?;
                target.parse::<std::net::SocketAddr>().with_context(|| {
                    format!("config: `remote_target_addr` = {target:?} is not a valid ip:port")
                })?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal in-memory config builder for the pure validation tests.
    fn cfg(role: Option<&str>, port: Option<u16>, target: Option<&str>) -> Config {
        Config {
            stun_servers: vec!["stun.l.google.com:19302".into()],
            punch_interval_ms: 500,
            punch_timeout_secs: 30,
            keep_alive_interval_secs: 5,
            local_tcp_listen_port: port,
            remote_target_addr: target.map(str::to_string),
            role: role.map(str::to_string),
            telegram: None,
        }
    }

    #[test]
    fn validate_for_role_client() {
        cfg(None, Some(12345), None)
            .validate_for_role(Role::Client)
            .unwrap();
        let err = cfg(None, None, None)
            .validate_for_role(Role::Client)
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("local_tcp_listen_port"), "{msg}");
        assert!(msg.contains("client role"), "{msg}");
    }

    #[test]
    fn validate_for_role_server() {
        cfg(None, None, Some("192.168.1.50:22"))
            .validate_for_role(Role::Server)
            .unwrap();
        let err = cfg(None, None, None)
            .validate_for_role(Role::Server)
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("remote_target_addr"), "{msg}");
        assert!(msg.contains("server role"), "{msg}");
        let err = cfg(None, None, Some("not-an-addr"))
            .validate_for_role(Role::Server)
            .unwrap_err();
        assert!(
            format!("{err:#}").contains("not a valid ip:port"),
            "{err:#}"
        );
    }

    #[test]
    fn declared_role_parses_and_rejects() {
        assert_eq!(
            cfg(Some("client"), None, None).declared_role(),
            Some(Role::Client)
        );
        assert_eq!(
            cfg(Some("Server"), None, None).declared_role(),
            Some(Role::Server)
        );
        assert_eq!(
            cfg(Some("  server "), None, None).declared_role(),
            Some(Role::Server)
        );
        assert_eq!(cfg(None, None, None).declared_role(), None);
        // Garbage is rejected at load time.
        let dir = std::env::temp_dir();
        let path = dir.join("p2p-tunnel-test-badrole.toml");
        std::fs::write(&path, "stun_servers = [\"a:1\"]\nrole = \"banana\"\n").unwrap();
        let err = Config::load(&path).unwrap_err();
        assert!(format!("{err:#}").contains("must be \"client\" or \"server\""));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn telegram_is_complete_matrix() {
        let base = TelegramConfig {
            token: "t".into(),
            peer_bot_id: 9,
            timeout_secs: 120,
            secret: Some("s".into()),
        };
        assert!(base.is_complete());
        assert!(
            !TelegramConfig {
                token: "  ".into(),
                ..base.clone()
            }
            .is_complete()
        );
        assert!(
            !TelegramConfig {
                peer_bot_id: 0,
                ..base.clone()
            }
            .is_complete()
        );
        assert!(
            !TelegramConfig {
                secret: None,
                ..base.clone()
            }
            .is_complete()
        );
        assert!(
            !TelegramConfig {
                secret: Some("   ".into()),
                ..base
            }
            .is_complete()
        );
    }

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
