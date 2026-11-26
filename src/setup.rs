//! Startup setup (v2): role selection + role-specific setting + channel.
//!
//! The v2 orchestration resolves everything the run needs beyond the config
//! file *before* the supervisor loop starts, in priority order:
//!
//! 1. CLI flag (`--role`),
//! 2. config file (`role`, `local_tcp_listen_port`, `remote_target_addr`),
//! 3. interactive prompt (TUI inline editor / plain stdin) — only when the
//!    value is missing, so a fully configured setup runs without prompts.
//!
//! The pure resolvers take an injected `read` closure so they can be tested
//! without a terminal; the [`setup`] entry point wires them to the real
//! [`TuiHandle`].

use std::io::Result as IoResult;
use std::net::SocketAddr;

use crate::cli;
use crate::config::Config;
use crate::role::Role;
use crate::tui::{PromptOutcome, SetupOutcome, TuiHandle};
use crate::tui_state::{ExchangeMode, SetupForm, ValidatedSetting, ValidatedSetup};

/// The role-specific setting the run needs beyond the config.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Setting {
    /// Client role: local TCP port to expose.
    Client(u16),
    /// Server role: service to forward to.
    Server(SocketAddr),
}

impl Setting {
    pub fn client_port(&self) -> Option<u16> {
        match self {
            Setting::Client(p) => Some(*p),
            Setting::Server(_) => None,
        }
    }

    pub fn server_target(&self) -> Option<SocketAddr> {
        match self {
            Setting::Server(a) => Some(*a),
            Setting::Client(_) => None,
        }
    }
}

/// Everything the supervisor loop needs for one attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Setup {
    pub role: Role,
    /// Address-exchange mode for this run (Telegram is the default when the
    /// `[telegram]` table is complete).
    pub channel: ExchangeMode,
    pub setting: Setting,
}

/// The validated `Setup` wrapper for the S1 screen. The form's `submit` can
/// only fail at validation time, so this conversion is infallible.
pub fn validated_to_setup(vs: ValidatedSetup) -> Setup {
    let setting = match vs.setting {
        ValidatedSetting::Client(p) => Setting::Client(p),
        ValidatedSetting::Server(a) => Setting::Server(a),
    };
    Setup {
        role: vs.role,
        channel: vs.channel,
        setting,
    }
}

/// The caller-known defaults for the S1 setup screen.
///
/// Built from the CLI flag + config before the screen opens. The screen
/// pre-fills from them — the operator confirms every value every run — and
/// never silently keeps them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SetupInitial {
    /// The role resolved from CLI/config (`--role` wins) — pre-filled.
    pub role: Option<Role>,
    /// The client-facing local TCP port (config value) — pre-filled.
    pub port: Option<u16>,
    /// The server-facing service (config value) — pre-filled.
    pub target: Option<String>,
    /// The address-exchange channel resolved from CLI/config.
    pub channel: ExchangeMode,
    /// Whether a working Telegram channel exists (arms the `t` toggle).
    pub telegram_available: bool,
}

impl SetupInitial {
    /// Build the pre-fill from CLI + config — the same priority the plain
    /// path uses, so the S1 screen starts where the run would start.
    pub fn from_config(cli: &cli::Cli, cfg: &Config) -> Self {
        let channel = resolve_channel(cli, cfg).unwrap_or(ExchangeMode::Manual);
        let role = cli
            .role
            .as_deref()
            .and_then(Role::parse)
            .or_else(|| cfg.declared_role());
        Self {
            role,
            port: cfg.local_tcp_listen_port,
            target: cfg.remote_target_addr.clone(),
            channel,
            telegram_available: channel == ExchangeMode::Telegram,
        }
    }

    /// The form the S1 screen starts with.
    pub fn setup_form(&self) -> SetupForm {
        SetupForm::new(
            self.role,
            self.port,
            self.target.as_deref(),
            self.channel,
            self.telegram_available,
        )
    }
}

/// The outcome of a setup prompt that terminated abnormally.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromptFailure {
    /// The user pressed q / Esc / Ctrl-C.
    Aborted,
    /// stdin is closed (non-interactive with nothing configured).
    Eof,
}

/// Fatal setup errors (bad CLI flag, misconfiguration) — no retry, no backoff.
/// A failure that stops setup but is not a fatal configuration error.
#[derive(Debug, PartialEq, Eq)]
pub enum SetupBail {
    /// The user quit (q / Esc / Ctrl-C) — clean exit.
    Aborted,
    /// stdin is closed / EOF — not an operator quit; fatal with a hint.
    Fatal(String),
}

/// Resolve the role: `--role` flag > config `role` > interactive prompt.
///
/// Returns `Ok(None)` when the role is not resolvable without a prompt *and*
/// the prompt cannot run (EOF in a non-interactive context). A CLI flag or a
/// config-declared role is used silently (no prompt) — the operator already
/// made the selection.
pub fn resolve_role(
    flag: Option<&str>,
    cfg: &Config,
    read: &mut dyn FnMut(&str) -> IoResult<PromptOutcome>,
) -> Result<Role, SetupBail> {
    if let Some(flag) = flag {
        return Role::parse(flag).ok_or_else(|| {
            SetupBail::Fatal(format!(
                "--role must be \"client\" or \"server\" (got {flag:?})"
            ))
        });
    }
    if let Some(role) = cfg.declared_role() {
        return Ok(role);
    }
    prompt_role(read)
}

/// Unconditionally prompt for the role (no config/flag fallback). Used when a
/// role conflict forces a re-selection: the answer must not be silently
/// inherited from the config, because the operator was just told the current
/// selection is wrong.
pub fn prompt_role(
    read: &mut dyn FnMut(&str) -> IoResult<PromptOutcome>,
) -> Result<Role, SetupBail> {
    loop {
        match read("Role (client/server): ").map_err(|_| SetupBail::Aborted)? {
            PromptOutcome::Line(line) => {
                let line = line.trim();
                if line.is_empty() {
                    continue; // no default: the user must pick explicitly
                }
                if let Some(role) = Role::parse(line) {
                    return Ok(role);
                }
                eprintln!(
                    "Invalid role '{line}' — expected \"client\" or \"server\". Please try again."
                );
            }
            PromptOutcome::ModeToggled => continue,
            PromptOutcome::Aborted => return Err(SetupBail::Aborted),
            PromptOutcome::Eof => {
                return Err(SetupBail::Fatal(
                    "no role selected and stdin is closed — pass --role <client|server> or set \
                     `role` in the config (see the sample config comments)"
                        .to_string(),
                ));
            }
        }
    }
}

/// Unconditionally prompt for the role-specific setting (no config fallback).
pub fn prompt_setting(
    role: Role,
    read: &mut dyn FnMut(&str) -> IoResult<PromptOutcome>,
) -> Result<Setting, SetupBail> {
    match role {
        Role::Client => prompt_client_setting(read),
        Role::Server => prompt_server_setting(read),
    }
}

fn prompt_client_setting(
    read: &mut dyn FnMut(&str) -> IoResult<PromptOutcome>,
) -> Result<Setting, SetupBail> {
    loop {
        match read("Local TCP port to expose (e.g. 12345): ").map_err(|_| SetupBail::Aborted)? {
            PromptOutcome::Line(line) => {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                match line.parse::<u16>() {
                    Ok(port) if port > 0 => return Ok(Setting::Client(port)),
                    Ok(_) => {
                        eprintln!("Port must be between 1 and 65535. Please try again.")
                    }
                    Err(_) => {
                        eprintln!("Invalid port '{line}' — enter a number between 1 and 65535.")
                    }
                }
            }
            PromptOutcome::ModeToggled => continue,
            PromptOutcome::Aborted => return Err(SetupBail::Aborted),
            PromptOutcome::Eof => {
                return Err(SetupBail::Fatal(
                    "no local TCP port configured and stdin is closed — set \
                     `local_tcp_listen_port` in the config (see the sample config comments)"
                        .to_string(),
                ));
            }
        }
    }
}

fn prompt_server_setting(
    read: &mut dyn FnMut(&str) -> IoResult<PromptOutcome>,
) -> Result<Setting, SetupBail> {
    loop {
        match read("Service to expose (ip:port, e.g. 192.168.1.50:22): ")
            .map_err(|_| SetupBail::Aborted)?
        {
            PromptOutcome::Line(line) => {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                match line.parse::<SocketAddr>() {
                    Ok(addr) => return Ok(Setting::Server(addr)),
                    Err(e) => {
                        eprintln!("Invalid address '{line}': {e}. Please try again.")
                    }
                }
            }
            PromptOutcome::ModeToggled => continue,
            PromptOutcome::Aborted => return Err(SetupBail::Aborted),
            PromptOutcome::Eof => {
                return Err(SetupBail::Fatal(
                    "no remote target configured and stdin is closed — set `remote_target_addr` \
                     in the config (see the sample config comments)"
                        .to_string(),
                ));
            }
        }
    }
}

/// Resolve the role-specific setting: config value (silent) or prompt.
pub fn resolve_setting(
    role: Role,
    cfg: &Config,
    read: &mut dyn FnMut(&str) -> IoResult<PromptOutcome>,
) -> Result<Setting, SetupBail> {
    match role {
        Role::Client => {
            if let Some(port) = cfg.local_tcp_listen_port {
                return Ok(Setting::Client(port));
            }
            prompt_client_setting(read)
        }
        Role::Server => {
            if let Some(target) = cfg.remote_target_addr.as_deref() {
                match target.trim().parse::<SocketAddr>() {
                    Ok(addr) => return Ok(Setting::Server(addr)),
                    Err(e) => {
                        return Err(SetupBail::Fatal(format!(
                            "config: `remote_target_addr` = {target:?} is not a valid ip:port ({e})"
                        )));
                    }
                }
            }
            prompt_server_setting(read)
        }
    }
}

/// Resolve the address-exchange channel for this run.
pub fn resolve_channel(cli: &cli::Cli, cfg: &Config) -> Result<ExchangeMode, SetupBail> {
    cli::resolve_exchange_mode(cli, cfg).map_err(SetupBail::Fatal)
}

/// The full startup setup: role, setting, channel — in priority order.
///
/// Returns [`SetupBail::Aborted`] when the user quits the prompt, or a fatal
/// error (misconfiguration / EOF with nothing configured) otherwise.
pub fn setup(cfg: &Config, cli: &cli::Cli, ui: &TuiHandle) -> Result<Setup, SetupBail> {
    setup_with(cfg, cli, &mut |prompt| ui.ask_line(prompt))
}

/// Run setup through the S1 TUI screen. When the handle is disabled (no TUI),
/// falls through to the plain stdin path — identical behavior to before.
///
/// `force_select`: the operator was just told the current selection is wrong
/// (a role conflict) — the screen starts EMPTY (no role/setting pre-fill),
/// because a stale selection must never silently survive the conflict.
///
/// Returns the `SetupOutcome`: `Submit` on a validated submission, or `Abort`
/// when the operator quits (q / Esc / Ctrl-C).
pub fn setup_tui(
    cfg: &Config,
    cli: &cli::Cli,
    ui: &TuiHandle,
    force_select: bool,
) -> Result<SetupOutcome, SetupBail> {
    if ui.is_disabled() {
        // Plain path — the pre-TUI behavior, unchanged.
        let outcome = if force_select {
            setup_force_select_with(cfg, cli, &mut |p| ui.ask_line(p))
        } else {
            setup_with(cfg, cli, &mut |p| ui.ask_line(p))
        };
        return outcome.map(|s| {
            SetupOutcome::Submit(ValidatedSetup {
                role: s.role,
                channel: s.channel,
                setting: match s.setting {
                    Setting::Client(p) => ValidatedSetting::Client(p),
                    Setting::Server(a) => ValidatedSetting::Server(a),
                },
            })
        });
    }

    let mut initial = SetupInitial::from_config(cli, cfg);
    if force_select {
        initial.role = None;
        initial.port = None;
        initial.target = None;
    }
    let form = initial.setup_form();
    match ui.ask_setup(form) {
        Some(outcome) => Ok(outcome),
        None => Err(SetupBail::Fatal(
            "setup screen was closed without a validated answer — press q to abort cleanly, \
             or pass --role <client|server> and a setting in the config"
                .to_string(),
        )),
    }
}

/// Force a fresh re-selection (used after a role conflict): the role and the
/// role-specific setting are always prompted — a stale config selection must
/// never silently survive being rejected. The channel is unchanged
/// (config/flag resolution still applies — the exchange channel is independent
/// of the role).
pub fn setup_force_select_with(
    cfg: &Config,
    cli: &cli::Cli,
    read: &mut dyn FnMut(&str) -> IoResult<PromptOutcome>,
) -> Result<Setup, SetupBail> {
    let role = prompt_role(read)?;
    let setting = prompt_setting(role, read)?;
    let channel = resolve_channel(cli, cfg)?;
    Ok(Setup {
        role,
        channel,
        setting,
    })
}

/// [`setup`] with an explicit reader — used by the tests.
pub fn setup_with(
    cfg: &Config,
    cli: &cli::Cli,
    read: &mut dyn FnMut(&str) -> IoResult<PromptOutcome>,
) -> Result<Setup, SetupBail> {
    let role = resolve_role(cli.role.as_deref(), cfg, read)?;
    let setting = resolve_setting(role, cfg, read)?;
    let channel = resolve_channel(cli, cfg)?;

    // The resolved setting is the contract for the run — validate that, not
    // (only) the config file: an interactively entered setting is valid by
    // construction, while a config value may still be the nonsense default.
    match setting {
        Setting::Client(port) => {
            if port == 0 {
                return Err(SetupBail::Fatal(
                    "config: `local_tcp_listen_port` must be between 1 and 65535 (got 0)"
                        .to_string(),
                ));
            }
        }
        Setting::Server(_) => {}
    }

    Ok(Setup {
        role,
        channel,
        setting,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli;

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

    fn cli_with_role(role: Option<&str>) -> cli::Cli {
        cli::Cli {
            config: std::path::PathBuf::from("config.toml"),
            verbose: false,
            telegram: false,
            manual: false,
            role: role.map(str::to_string),
            tui: false,
            no_tui: false,
        }
    }

    /// A scripted `read`: returns the given outcomes in order.
    fn script(outcomes: Vec<PromptOutcome>) -> impl FnMut(&str) -> IoResult<PromptOutcome> {
        let mut it = outcomes.into_iter();
        move |_prompt| {
            let next = it.next().expect("script exhausted");
            Ok(next)
        }
    }

    #[test]
    fn role_flag_wins_silently_over_config_and_prompt() {
        let c = cfg(Some("client"), Some(12345), None);
        // Even with a prompt script present, a flag/config role never prompts.
        let mut read = script(vec![PromptOutcome::Line("server".into())]);
        let role = resolve_role(Some("server"), &c, &mut read).unwrap();
        assert_eq!(role, Role::Server);
    }

    #[test]
    fn config_role_wins_over_prompt() {
        let c = cfg(Some("server"), None, Some("127.0.0.1:22"));
        let mut read = script(vec![PromptOutcome::Line("client".into())]);
        let role = resolve_role(None, &c, &mut read).unwrap();
        assert_eq!(role, Role::Server);
    }

    #[test]
    fn prompt_used_when_no_config_or_flag() {
        let c = cfg(None, None, None);
        let mut read = script(vec![PromptOutcome::Line("client".into())]);
        let role = resolve_role(None, &c, &mut read).unwrap();
        assert_eq!(role, Role::Client);
    }

    #[test]
    fn prompt_reprompts_on_empty_and_garbage_input() {
        let c = cfg(None, Some(12345), None);
        let mut read = script(vec![
            PromptOutcome::Line("".into()),
            PromptOutcome::Line("garbage".into()),
            PromptOutcome::Line("  server  ".into()),
        ]);
        let role = resolve_role(None, &c, &mut read).unwrap();
        assert_eq!(role, Role::Server);
    }

    #[test]
    fn prompt_abort_propagates() {
        let c = cfg(None, None, None);
        let mut read = script(vec![PromptOutcome::Aborted]);
        let err = resolve_role(None, &c, &mut read).unwrap_err();
        assert_eq!(err, SetupBail::Aborted);
    }

    #[test]
    fn prompt_eof_is_fatal_with_hint() {
        let c = cfg(None, None, None);
        let mut read = script(vec![PromptOutcome::Eof]);
        let err = resolve_role(None, &c, &mut read).unwrap_err();
        assert!(matches!(err, SetupBail::Fatal(m) if m.contains("--role")));
    }

    #[test]
    fn client_setting_from_config_is_silent() {
        let c = cfg(Some("client"), Some(12345), None);
        let mut read = script(vec![]);
        let setting = resolve_setting(Role::Client, &c, &mut read).unwrap();
        assert_eq!(setting, Setting::Client(12345));
    }

    #[test]
    fn client_setting_prompts_when_missing() {
        let c = cfg(Some("client"), None, None);
        let mut read = script(vec![PromptOutcome::Line("80".into())]);
        let setting = resolve_setting(Role::Client, &c, &mut read).unwrap();
        assert_eq!(setting, Setting::Client(80));
    }

    #[test]
    fn client_setting_rejects_zero_and_garbage() {
        let c = cfg(Some("client"), None, None);
        let mut read = script(vec![
            PromptOutcome::Line("0".into()),
            PromptOutcome::Line("abc".into()),
            PromptOutcome::Line("12345".into()),
        ]);
        let setting = resolve_setting(Role::Client, &c, &mut read).unwrap();
        assert_eq!(setting, Setting::Client(12345));
    }

    #[test]
    fn server_setting_from_config_is_silent() {
        let c = cfg(Some("server"), None, Some("127.0.0.1:22"));
        let mut read = script(vec![]);
        let setting = resolve_setting(Role::Server, &c, &mut read).unwrap();
        assert_eq!(setting, Setting::Server("127.0.0.1:22".parse().unwrap()));
    }

    #[test]
    fn server_setting_invalid_config_is_fatal() {
        let c = cfg(Some("server"), None, Some("not-an-addr"));
        let mut read = script(vec![]);
        let err = resolve_setting(Role::Server, &c, &mut read).unwrap_err();
        assert!(matches!(err, SetupBail::Fatal(m) if m.contains("not-an-addr")));
    }

    #[test]
    fn server_setting_prompts_when_missing() {
        let c = cfg(Some("server"), None, None);
        let mut read = script(vec![PromptOutcome::Line("192.168.1.50:22".into())]);
        let setting = resolve_setting(Role::Server, &c, &mut read).unwrap();
        assert_eq!(setting, Setting::Server("192.168.1.50:22".parse().unwrap()));
    }

    #[test]
    fn setting_abort_propagates() {
        let c = cfg(Some("client"), None, None);
        let mut read = script(vec![PromptOutcome::Aborted]);
        let err = resolve_setting(Role::Client, &c, &mut read).unwrap_err();
        assert_eq!(err, SetupBail::Aborted);
    }

    #[test]
    fn setup_full_config_never_prompts() {
        let c = cfg(Some("server"), None, Some("127.0.0.1:22"));
        let cli = cli_with_role(None);
        // No prompt should ever be issued: a script with zero outcomes would
        // panic if one were called.
        let mut read = script(vec![]);
        let s = setup_with(&c, &cli, &mut read).unwrap();
        assert_eq!(s.role, Role::Server);
        assert_eq!(s.setting, Setting::Server("127.0.0.1:22".parse().unwrap()));
    }

    #[test]
    fn setup_bad_flag_is_fatal() {
        let c = cfg(None, Some(12345), None);
        let cli = cli_with_role(Some("bogus"));
        let mut read = script(vec![]);
        let err = setup_with(&c, &cli, &mut read).unwrap_err();
        assert!(matches!(err, SetupBail::Fatal(m) if m.contains("--role")));
    }

    #[test]
    fn setup_eof_with_nothing_configured_is_fatal_with_hint() {
        let c = cfg(None, None, None);
        let cli = cli_with_role(None);
        let mut read = script(vec![PromptOutcome::Eof]);
        let err = setup_with(&c, &cli, &mut read).unwrap_err();
        assert!(matches!(err, SetupBail::Fatal(m) if m.contains("--role")));
    }

    #[test]
    fn force_select_prompts_even_with_full_config() {
        // A stale config selection must never silently survive a role
        // conflict: the operator is re-prompted for role AND setting.
        let c = cfg(Some("server"), None, Some("127.0.0.1:22"));
        let cli = cli_with_role(None);
        let mut read = script(vec![
            PromptOutcome::Line("client".into()),
            PromptOutcome::Line("12345".into()),
        ]);
        let s = setup_force_select_with(&c, &cli, &mut read).unwrap();
        assert_eq!(s.role, Role::Client);
        assert_eq!(s.setting, Setting::Client(12345));
    }

    #[test]
    fn force_select_prompts_server_setting_when_role_changed() {
        let c = cfg(Some("client"), Some(12345), None);
        let cli = cli_with_role(None);
        let mut read = script(vec![
            PromptOutcome::Line("server".into()),
            PromptOutcome::Line("127.0.0.1:22".into()),
        ]);
        let s = setup_force_select_with(&c, &cli, &mut read).unwrap();
        assert_eq!(s.role, Role::Server);
        assert_eq!(s.setting, Setting::Server("127.0.0.1:22".parse().unwrap()));
    }

    #[test]
    fn force_select_eof_is_fatal_with_hint() {
        let c = cfg(Some("server"), None, Some("127.0.0.1:22"));
        let cli = cli_with_role(None);
        let mut read = script(vec![PromptOutcome::Eof]);
        let err = setup_force_select_with(&c, &cli, &mut read).unwrap_err();
        assert!(matches!(err, SetupBail::Fatal(m) if m.contains("--role")));
    }

    #[test]
    fn force_select_abort_propagates() {
        let c = cfg(Some("server"), None, Some("127.0.0.1:22"));
        let cli = cli_with_role(None);
        let mut read = script(vec![PromptOutcome::Aborted]);
        let err = setup_force_select_with(&c, &cli, &mut read).unwrap_err();
        assert_eq!(err, SetupBail::Aborted);
    }
}
