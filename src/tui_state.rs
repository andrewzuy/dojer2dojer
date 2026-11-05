//! The TUI's renderable state — a pure, serializable snapshot of what the UI
//! shows. Kept separate from [`crate::tui`] so it can be unit-tested without a
//! terminal.

use std::collections::HashMap;

use crate::tui::LogLevel;

/// The six lifecycle phases the stepper visualizes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Phase {
    Stun,
    Exchange,
    Punch,
    Role,
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

/// The full UI state. `Clone` so the draw function can snapshot it cheaply.
#[derive(Clone, Debug, Default)]
pub struct TuiState {
    pub phase_status: HashMap<Phase, PhaseStatus>,
    pub own_addr: Option<String>,
    pub peer_addr: Option<String>,
    pub role: Option<String>,
    pub fingerprint: Option<String>,
    pub local_port: Option<u16>,
    pub target: Option<String>,
    pub ready: bool,
    pub done: bool,
    pub error: bool,
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
}

/// How many log lines to keep in memory.
const MAX_LOG_LINES: usize = 500;

impl TuiState {
    pub fn set_phase(&mut self, phase: Phase, status: PhaseStatus) {
        // Whenever a phase becomes Active/Done/Error, any *earlier* phase that
        // is still Active is completed, so the stepper never shows two
        // actives at once (progress only moves forward).
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

    pub fn push_log(&mut self, level: LogLevel, msg: String) {
        self.logs.push((level, msg));
        if self.logs.len() > MAX_LOG_LINES {
            let drop = self.logs.len() - MAX_LOG_LINES;
            self.logs.drain(..drop);
        }
    }
}

/// Canonical phase order for the stepper.
fn phase_order() -> [Phase; 6] {
    [
        Phase::Stun,
        Phase::Exchange,
        Phase::Punch,
        Phase::Role,
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
        s.set_phase(Phase::Stun, PhaseStatus::Active);
        assert_eq!(s.status(Phase::Stun), PhaseStatus::Active);

        // Moving to Exchange active should mark Stun done (no two actives).
        s.set_phase(Phase::Exchange, PhaseStatus::Active);
        assert_eq!(s.status(Phase::Stun), PhaseStatus::Done);
        assert_eq!(s.status(Phase::Exchange), PhaseStatus::Active);

        // Marking Exchange done advances to the next.
        s.set_phase(Phase::Exchange, PhaseStatus::Done);
        assert_eq!(s.status(Phase::Exchange), PhaseStatus::Done);
    }

    #[test]
    fn active_phase_reports_frontier() {
        let mut s = TuiState::default();
        assert_eq!(s.active_phase(), Phase::Stun);
        s.set_phase(Phase::Stun, PhaseStatus::Active);
        assert_eq!(s.active_phase(), Phase::Stun);
        s.set_phase(Phase::Stun, PhaseStatus::Done);
        s.set_phase(Phase::Exchange, PhaseStatus::Active);
        assert_eq!(s.active_phase(), Phase::Exchange);
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
    fn logs_are_bounded() {
        let mut s = TuiState::default();
        for i in 0..(MAX_LOG_LINES + 100) {
            s.push_log(LogLevel::Info, format!("line {i}"));
        }
        assert_eq!(s.logs.len(), MAX_LOG_LINES);
        // Oldest lines were dropped.
        assert_eq!(s.logs.first().unwrap().1, "line 100");
    }
}
