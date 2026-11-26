//! The TUI's renderable state — a pure, serializable snapshot of what the UI
//! shows. Kept separate from [`crate::tui`] so it can be unit-tested without a
//! terminal.

use std::collections::HashMap;
use std::net::SocketAddr;

use crate::role::Role;
use crate::tui::LogLevel;

/// The seven lifecycle phases the stepper visualizes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Phase {
    /// Startup setup (role + setting + channel, or a forced re-selection after
    /// a role conflict).
    Setup,
    Stun,
    Exchange,
    Punch,
    /// The Telegram role cross-check (`PTUN READY` + `PTUN ROLE`). The phase
    /// is `Skipped` when the run has no Telegram channel (manual mode).
    RoleCheck,
    Quic,
    Tunnel,
}

/// A phase's current status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PhaseStatus {
    Pending,
    Active,
    Done,
    Error,
    /// The phase does not apply to this run (e.g. the role cross-check in
    /// manual mode).
    Skipped,
}

/// How the peer's public address is being resolved (the Exchange phase).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ExchangeMode {
    /// The user types the peer's address at the prompt.
    #[default]
    Manual,
    /// The Telegram bots DM each other's addresses.
    Telegram,
}

impl ExchangeMode {
    pub fn as_str(self) -> &'static str {
        match self {
            ExchangeMode::Manual => "manual",
            ExchangeMode::Telegram => "telegram",
        }
    }

    /// Wire format for the mode flag shared between the pipeline and the
    /// render loop (`AtomicU8` is not generic over enums).
    pub const MANUAL_BITS: u8 = 0;
    pub const TELEGRAM_BITS: u8 = 1;

    pub fn to_bits(self) -> u8 {
        match self {
            ExchangeMode::Manual => Self::MANUAL_BITS,
            ExchangeMode::Telegram => Self::TELEGRAM_BITS,
        }
    }

    pub fn from_bits(b: u8) -> Self {
        match b {
            Self::TELEGRAM_BITS => ExchangeMode::Telegram,
            _ => ExchangeMode::Manual,
        }
    }
}

/// Which field of the S1 setup screen is focused.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SetupField {
    /// The role row (←/→ or c/s).
    #[default]
    Role,
    /// The role-specific draft (port / service).
    Setting,
}

/// What happened as a result of applying a key to the S1 form.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FormKeyOutcome {
    /// The key was consumed by the form (the screen redraws).
    Consumed,
    /// Nothing meaningful happened (e.g. a stray key).
    Ignored,
    /// Enter arrived — the screen should validate and submit.
    Submit,
    /// `q` / Esc / Ctrl-C — the screen should abort.
    Abort,
}

/// The role-specific setting produced by the S1 form.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ValidatedSetting {
    /// Client role: the local TCP port the operator connects to.
    Client(u16),
    /// Server role: the service to expose.
    Server(SocketAddr),
}

/// The validated, user-confirmed setup produced by the S1 screen.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedSetup {
    /// The selected role.
    pub role: Role,
    /// The address-exchange channel.
    pub channel: ExchangeMode,
    /// The validated role-specific setting.
    pub setting: ValidatedSetting,
}

/// The keyboard input recognized by the S1 setup screen. Kept as a plain enum
/// (not `crossterm::event::KeyCode`) so the form is testable without a
/// terminal; the render loop maps the key events down to this.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FormKey {
    Left,
    Right,
    Up,
    Down,
    Tab,
    Enter,
    Backspace,
    Esc,
    CtrlC,
    Char(char),
    /// Anything else — the form ignores it.
    Unhandled,
}

/// The S1 setup screen's mutable state machine. The pipeline only reads the
/// validated result; everything interactive is handled here so the screen can
/// be unit-tested without a terminal.
#[derive(Clone, Debug, PartialEq)]
pub struct SetupForm {
    /// The selected role (`None` = not chosen yet).
    pub role: Option<Role>,
    /// The address-exchange channel.
    pub channel: ExchangeMode,
    /// Which field is focused.
    pub focused: SetupField,
    /// The client-facing draft (local TCP port).
    pub port: String,
    /// The server-facing draft (service to expose).
    pub target: String,
    /// The last validation error (shown in red on the screen), cleared on the
    /// next keystroke.
    pub error: Option<String>,
    /// Whether a working Telegram channel exists (arms the `t` toggle).
    pub telegram_available: bool,
}

impl SetupForm {
    /// Build the form from the caller's known-good defaults.
    pub fn new(
        role: Option<Role>,
        port: Option<u16>,
        target: Option<&str>,
        channel: ExchangeMode,
        telegram_available: bool,
    ) -> Self {
        Self {
            role,
            channel,
            focused: SetupField::Role,
            port: port.map(|p| p.to_string()).unwrap_or_default(),
            target: target.unwrap_or_default().to_string(),
            error: None,
            telegram_available,
        }
    }

    /// Whether the Setting field is meaningful right now (a role is chosen).
    pub fn has_field(&self) -> bool {
        self.role.is_some()
    }

    /// The label for the role-specific setting.
    pub fn field_label(&self) -> &'static str {
        match self.role {
            Some(Role::Client) => "local port",
            Some(Role::Server) => "service to expose",
            None => "role required — pick one first",
        }
    }

    /// The draft text under focus (for display).
    pub fn focused_draft(&self) -> &str {
        match self.role {
            Some(Role::Client) => &self.port,
            Some(Role::Server) => &self.target,
            None => "",
        }
    }

    /// An example placeholder for a fresh draft.
    pub fn draft_placeholder(&self) -> &'static str {
        match self.role {
            Some(Role::Client) => "e.g. 12345",
            Some(Role::Server) => "e.g. 192.168.1.50:22",
            None => "",
        }
    }

    /// Apply one keystroke. The screen redraws from the returned state.
    pub fn apply(&mut self, key: FormKey) -> FormKeyOutcome {
        self.error = None;
        match key {
            // `q`/`Q` abort — intercepted before the edit-path so a stray `q`
            // in the draft can't be confused with a quit.
            FormKey::Esc | FormKey::CtrlC => FormKeyOutcome::Abort,
            FormKey::Char('q') | FormKey::Char('Q') => FormKeyOutcome::Abort,
            FormKey::Enter => FormKeyOutcome::Submit,
            FormKey::Up => {
                self.focused = SetupField::Role;
                FormKeyOutcome::Consumed
            }
            FormKey::Down => {
                if self.role.is_some() {
                    self.focused = SetupField::Setting;
                }
                FormKeyOutcome::Consumed
            }
            FormKey::Tab => {
                if !self.has_field() {
                    // No role yet — the Setting field is not meaningful.
                    return FormKeyOutcome::Consumed;
                }
                self.focused = match self.focused {
                    SetupField::Role => SetupField::Setting,
                    SetupField::Setting => SetupField::Role,
                };
                FormKeyOutcome::Consumed
            }
            FormKey::Left => {
                self.role = Some(Role::Client);
                FormKeyOutcome::Consumed
            }
            FormKey::Right => {
                self.role = Some(Role::Server);
                FormKeyOutcome::Consumed
            }
            FormKey::Backspace => {
                if self.focused == SetupField::Setting {
                    match self.role {
                        Some(Role::Client) => {
                            self.port.pop();
                        }
                        Some(Role::Server) => {
                            self.target.pop();
                        }
                        None => {}
                    }
                }
                FormKeyOutcome::Consumed
            }
            FormKey::Char('c') | FormKey::Char('C') => {
                self.role = Some(Role::Client);
                FormKeyOutcome::Consumed
            }
            FormKey::Char('s') | FormKey::Char('S') => {
                self.role = Some(Role::Server);
                FormKeyOutcome::Consumed
            }
            FormKey::Char('t') | FormKey::Char('T') => {
                if self.telegram_available {
                    self.channel = match self.channel {
                        ExchangeMode::Manual => ExchangeMode::Telegram,
                        ExchangeMode::Telegram => ExchangeMode::Manual,
                    };
                }
                FormKeyOutcome::Consumed
            }
            FormKey::Char(c) => {
                if self.focused == SetupField::Setting
                    && self.role.is_some()
                    && c.is_ascii_graphic()
                {
                    match self.role {
                        Some(Role::Client) => {
                            if c.is_ascii_digit() {
                                self.port.push(c);
                            }
                        }
                        Some(Role::Server) => self.target.push(c),
                        None => {}
                    }
                }
                FormKeyOutcome::Consumed
            }
            FormKey::Unhandled => FormKeyOutcome::Ignored,
        }
    }

    /// Validate the form. On success returns the validated setup; on failure
    /// returns the error message to display.
    pub fn submit(&self) -> Result<ValidatedSetup, String> {
        let Some(role) = self.role else {
            return Err("pick a role — arrow keys or c/s".into());
        };
        let setting = match role {
            Role::Client => {
                let raw = self.port.trim();
                if raw.is_empty() {
                    return Err("enter a local TCP port (e.g. 12345)".into());
                }
                match raw.parse::<u16>() {
                    Ok(0) => return Err("port must be between 1 and 65535".into()),
                    Ok(port) => ValidatedSetting::Client(port),
                    Err(_) => {
                        return Err(format!(
                            "invalid port '{raw}' — enter a number between 1 and 65535"
                        ));
                    }
                }
            }
            Role::Server => {
                let raw = self.target.trim();
                if raw.is_empty() {
                    return Err("enter a service to expose (e.g. 192.168.1.50:22)".into());
                }
                match raw.parse::<SocketAddr>() {
                    Ok(addr) => ValidatedSetting::Server(addr),
                    Err(e) => return Err(format!("invalid address '{raw}': {e}")),
                }
            }
        };
        Ok(ValidatedSetup {
            role,
            channel: self.channel,
            setting,
        })
    }
}

/// The full UI state. `Clone` so the draw function can snapshot it cheaply.
#[derive(Clone, Debug, Default)]
pub struct TuiState {
    pub phase_status: HashMap<Phase, PhaseStatus>,
    pub own_addr: Option<String>,
    pub peer_addr: Option<String>,
    /// The peer's declared role (from the READY handshake) — `None` on the
    /// manual path or with a legacy peer.
    pub peer_role: Option<String>,
    pub fingerprint: Option<String>,
    pub local_port: Option<u16>,
    pub target: Option<String>,
    pub ready: bool,
    pub done: bool,
    pub error: bool,
    /// The fatal error text (shown in the red banner).
    pub error_msg: Option<String>,
    /// The most recent role-conflict message (shown on the setup screen).
    pub role_conflict: Option<String>,
    /// The S1 setup screen's live form, while it is open.
    pub setup_form: Option<SetupForm>,
    /// The most recent event log lines (bounded to avoid unbounded growth).
    pub logs: Vec<(LogLevel, String)>,
    /// Advances on each render tick to drive the spinner.
    pub tick: u32,
    /// The current address-exchange mode (mirrored from the shared flag the
    /// render loop flips when the user presses `t`).
    pub exchange_mode: ExchangeMode,
    /// Whether a working Telegram channel exists (drives the `t` hint and
    /// blocks the toggle when Telegram is not configured).
    pub telegram_available: bool,
    /// `Some((prompt text, input so far))` while an interactive prompt is
    /// active; the input line is rendered at the bottom of the screen.
    pub prompt: Option<(String, String)>,
    /// The user-selected role from startup setup (what the operator told us to
    /// do), shown in the connection panel next to the peer's declared role.
    pub selected_role: Option<String>,
    /// The current supervisor attempt number (1-based), or `None` before the
    /// first attempt begins.
    pub attempt: Option<u32>,
    /// True while the tunnel is down and the supervisor is waiting before the
    /// next attempt (the operator sees this in the footer).
    pub renegotiating: bool,
    /// The most recent re-negotiation reason (shown in the footer).
    pub renegotiating_msg: Option<String>,
}

/// How many log lines to keep in memory.
const MAX_LOG_LINES: usize = 500;

impl TuiState {
    pub fn set_phase(&mut self, phase: Phase, status: PhaseStatus) {
        // Whenever a phase becomes non-Active, any *earlier* phase that is
        // still Active is completed, so the stepper never shows two actives at
        // once (progress only moves forward).
        if !matches!(status, PhaseStatus::Pending) {
            let order = phase_order();
            let idx = order.iter().position(|p| *p == phase).unwrap_or(0);
            for earlier in &order[..idx] {
                if self.status(*earlier) == PhaseStatus::Active {
                    self.phase_status.insert(*earlier, PhaseStatus::Done);
                }
            }
        }
        self.phase_status.insert(phase, status);
    }

    pub fn status(&self, phase: Phase) -> PhaseStatus {
        self.phase_status
            .get(&phase)
            .copied()
            .unwrap_or(PhaseStatus::Pending)
    }

    pub fn active_phase(&self) -> Phase {
        // The first phase in order that is Active; fall back to the first
        // pending one so the footer always names something sensible.
        for p in phase_order() {
            if self.status(p) == PhaseStatus::Active {
                return p;
            }
        }
        phase_order()
            .iter()
            .copied()
            .find(|p| self.status(*p) == PhaseStatus::Pending)
            .unwrap_or(Phase::Tunnel)
    }

    /// Reset the per-attempt fields for a new supervisor attempt. Logs, the
    /// selected role, the Telegram availability flag, the channel, the Setup
    /// phase status, and the role-conflict slot survive across attempts (they
    /// belong to the app, not the attempt).
    pub fn reset_for_attempt(&mut self, attempt: u32) {
        let setup_status = self.status(Phase::Setup);
        self.phase_status.clear();
        if setup_status != PhaseStatus::Pending {
            self.phase_status.insert(Phase::Setup, setup_status);
        }
        self.own_addr = None;
        self.peer_addr = None;
        self.peer_role = None;
        self.fingerprint = None;
        self.local_port = None;
        self.target = None;
        self.ready = false;
        self.done = false;
        self.error = false;
        self.prompt = None;
        self.attempt = Some(attempt);
        self.renegotiating = false;
        self.renegotiating_msg = None;
        self.role_conflict = None;
        self.error_msg = None;
        self.setup_form = None;
    }

    pub fn push_log(&mut self, level: LogLevel, msg: String) {
        self.logs.push((level, msg));
        if self.logs.len() > MAX_LOG_LINES {
            let drop = self.logs.len() - MAX_LOG_LINES;
            self.logs.drain(..drop);
        }
    }
}

/// Canonical phase order for the stepper.
fn phase_order() -> [Phase; 7] {
    [
        Phase::Setup,
        Phase::Stun,
        Phase::Exchange,
        Phase::Punch,
        Phase::RoleCheck,
        Phase::Quic,
        Phase::Tunnel,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phase_transitions_advance_stuck_actives() {
        let mut s = TuiState::default();
        s.set_phase(Phase::Setup, PhaseStatus::Active);
        assert_eq!(s.status(Phase::Setup), PhaseStatus::Active);

        // Moving to Stun active should mark Setup done (no two actives).
        s.set_phase(Phase::Stun, PhaseStatus::Active);
        assert_eq!(s.status(Phase::Setup), PhaseStatus::Done);
        assert_eq!(s.status(Phase::Stun), PhaseStatus::Active);

        // Marking Stun done advances to the next.
        s.set_phase(Phase::Stun, PhaseStatus::Done);
        assert_eq!(s.status(Phase::Stun), PhaseStatus::Done);
    }

    #[test]
    fn skipped_phase_counts_as_non_pending() {
        let mut s = TuiState::default();
        // A skipped role cross-check completes earlier actives like any other
        // non-Pending status.
        s.set_phase(Phase::Exchange, PhaseStatus::Active);
        s.set_phase(Phase::RoleCheck, PhaseStatus::Skipped);
        assert_eq!(s.status(Phase::RoleCheck), PhaseStatus::Skipped);
        assert_eq!(s.status(Phase::Exchange), PhaseStatus::Done);
    }

    #[test]
    fn active_phase_reports_frontier() {
        let mut s = TuiState::default();
        assert_eq!(s.active_phase(), Phase::Setup);
        s.set_phase(Phase::Setup, PhaseStatus::Active);
        assert_eq!(s.active_phase(), Phase::Setup);
        s.set_phase(Phase::Setup, PhaseStatus::Done);
        s.set_phase(Phase::Stun, PhaseStatus::Active);
        assert_eq!(s.active_phase(), Phase::Stun);
    }

    #[test]
    fn exchange_mode_round_trips_through_bits() {
        assert_eq!(ExchangeMode::Manual.to_bits(), 0);
        assert_eq!(ExchangeMode::Telegram.to_bits(), 1);
        assert_eq!(ExchangeMode::from_bits(0), ExchangeMode::Manual);
        assert_eq!(ExchangeMode::from_bits(1), ExchangeMode::Telegram);
        assert_eq!(ExchangeMode::from_bits(99), ExchangeMode::Manual);
    }

    #[test]
    fn reset_for_attempt_clears_per_attempt_fields() {
        let mut s = TuiState {
            own_addr: Some("1.2.3.4:5".into()),
            peer_addr: Some("9.9.9.9:5".into()),
            peer_role: Some("client".into()),
            fingerprint: Some("ff".into()),
            ready: true,
            done: true,
            error: true,
            role_conflict: Some("conflict".into()),
            error_msg: Some("boom".into()),
            setup_form: Some(SetupForm::new(
                Some(Role::Client),
                Some(12345),
                None,
                ExchangeMode::Manual,
                false,
            )),
            selected_role: Some("server".into()),
            renegotiating: true,
            ..TuiState::default()
        };
        s.set_phase(Phase::Setup, PhaseStatus::Done);
        s.set_phase(Phase::Stun, PhaseStatus::Active);
        s.push_log(LogLevel::Info, "kept".into());
        s.reset_for_attempt(3);
        assert_eq!(s.attempt, Some(3));
        assert!(!s.renegotiating);
        assert!(s.own_addr.is_none() && s.peer_addr.is_none() && s.peer_role.is_none());
        assert!(!s.ready && !s.done && !s.error);
        assert!(s.role_conflict.is_none() && s.error_msg.is_none() && s.setup_form.is_none());
        assert_eq!(s.status(Phase::Stun), PhaseStatus::Pending);
        // The Setup phase survives (it is app-lifetime; the operator still
        // sees the selected role on the screen).
        assert_eq!(s.status(Phase::Setup), PhaseStatus::Done);
        // App-lifetime fields survive.
        assert_eq!(s.selected_role.as_deref(), Some("server"));
        assert_eq!(s.logs.len(), 1);
        assert_eq!(s.logs[0].1, "kept");
    }

    #[test]
    fn logs_are_bounded() {
        let mut s = TuiState::default();
        for i in 0..(MAX_LOG_LINES + 100) {
            s.push_log(LogLevel::Info, format!("line {i}"));
        }
        assert_eq!(s.logs.len(), MAX_LOG_LINES);
        // Oldest lines were dropped.
        assert_eq!(s.logs.first().unwrap().1, "line 100");
    }

    #[test]
    fn setup_form_submits_client_when_valid() {
        let mut f = SetupForm::new(None, None, None, ExchangeMode::Telegram, true);
        assert_eq!(f.apply(FormKey::Right), FormKeyOutcome::Consumed);
        assert_eq!(f.role, Some(Role::Server));
        let _ = f.apply(FormKey::Down);
        for c in "10.0.0.1:22".chars() {
            f.apply(FormKey::Char(c));
        }
        assert_eq!(f.apply(FormKey::Enter), FormKeyOutcome::Submit);
        let validated = f.submit().unwrap();
        assert_eq!(validated.role, Role::Server);
        assert_eq!(validated.channel, ExchangeMode::Telegram);
        assert_eq!(
            validated.setting,
            ValidatedSetting::Server("10.0.0.1:22".parse().unwrap())
        );
    }

    #[test]
    fn setup_form_client_port_round_trip() {
        let mut f = SetupForm::new(
            Some(Role::Client),
            Some(12345),
            None,
            ExchangeMode::Manual,
            false,
        );
        assert_eq!(f.port, "12345");
        assert_eq!(f.apply(FormKey::Enter), FormKeyOutcome::Submit);
        let validated = f.submit().unwrap();
        assert_eq!(validated.setting, ValidatedSetting::Client(12345));
        assert_eq!(validated.channel, ExchangeMode::Manual);
    }

    #[test]
    fn setup_form_rejects_missing_role() {
        let f = SetupForm::new(None, Some(12345), None, ExchangeMode::Manual, false);
        let err = f.submit().unwrap_err();
        assert!(err.contains("role"));
    }

    #[test]
    fn setup_form_rejects_bad_port() {
        let mut f = SetupForm::new(
            Some(Role::Client),
            Some(12345),
            None,
            ExchangeMode::Manual,
            false,
        );
        f.port = "not-a-port".into();
        let err = f.submit().unwrap_err();
        assert!(err.contains("invalid port"));

        // Port 0 is not a valid local listen port.
        let mut f = SetupForm::new(
            Some(Role::Client),
            Some(12345),
            None,
            ExchangeMode::Manual,
            false,
        );
        f.port = "0".into();
        let err = f.submit().unwrap_err();
        assert!(err.contains("between 1 and 65535"));

        // Empty port.
        let f = SetupForm::new(Some(Role::Client), None, None, ExchangeMode::Manual, false);
        let err = f.submit().unwrap_err();
        assert!(err.contains("local TCP port"));
    }

    #[test]
    fn setup_form_rejects_bad_target_address() {
        let mut f = SetupForm::new(Some(Role::Server), None, None, ExchangeMode::Manual, false);
        f.target = "not-an-address".into();
        let err = f.submit().unwrap_err();
        assert!(err.contains("invalid address"));
    }

    #[test]
    fn setup_form_backspace_and_edit_only_on_setting_field() {
        let mut f = SetupForm::new(
            Some(Role::Client),
            Some(12345),
            None,
            ExchangeMode::Manual,
            false,
        );
        // In the role field, Backspace is inert.
        f.focused = SetupField::Role;
        let before = f.port.clone();
        f.apply(FormKey::Backspace);
        assert_eq!(f.port, before);
        // Tab into the setting field, then Backspace pops the port.
        f.apply(FormKey::Tab);
        assert_eq!(f.focused, SetupField::Setting);
        f.apply(FormKey::Backspace);
        assert_eq!(f.port, "1234");
    }

    #[test]
    fn setup_form_toggles_channel_only_when_telegram_available() {
        let mut f = SetupForm::new(
            Some(Role::Client),
            Some(12345),
            None,
            ExchangeMode::Manual,
            false,
        );
        f.apply(FormKey::Char('t'));
        assert_eq!(f.channel, ExchangeMode::Manual);

        let mut f = SetupForm::new(
            Some(Role::Client),
            Some(12345),
            None,
            ExchangeMode::Manual,
            true,
        );
        f.apply(FormKey::Char('t'));
        assert_eq!(f.channel, ExchangeMode::Telegram);
        f.apply(FormKey::Char('t'));
        assert_eq!(f.channel, ExchangeMode::Manual);
    }

    #[test]
    fn setup_form_q_aborts() {
        let mut f = SetupForm::new(
            Some(Role::Client),
            Some(12345),
            None,
            ExchangeMode::Manual,
            false,
        );
        f.focused = SetupField::Setting;
        assert_eq!(f.apply(FormKey::Char('q')), FormKeyOutcome::Abort);
    }

    #[test]
    fn setup_form_keeps_error_until_next_keystroke() {
        let mut f = SetupForm::new(None, None, None, ExchangeMode::Manual, false);
        assert!(f.submit().is_err());
        f.error = Some("x".into());
        f.apply(FormKey::Unhandled);
        assert!(f.error.is_none());
    }
}
