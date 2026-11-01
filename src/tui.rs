//! Live, cross-platform TUI that visualizes the tunnel lifecycle.
//!
//! The tunnel pipeline is unchanged; it reports progress by emitting
//! [`TuiEvent`]s over an [`mpsc::unbounded_channel`]. A dedicated render loop
//! owns the terminal (via ratatui + crossterm) and paints the current state.
//!
//! Rendering is *completely decoupled* from the network code: no pipeline
//! function calls a UI routine. They only hand the sender a message. That keeps
//! the async logic testable and the UI a pure function of the event stream.
//!
//! The TUI is opt-in (`--tui`) and also auto-enabled when stdout is a TTY and
//! `--no-tui` is not given. When the TUI is off, the plain `tracing` log path
//! runs exactly as before — there is no regression.

use std::sync::mpsc;

use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph};
use ratatui::{Frame, Terminal};

use crate::tui_state::{Phase, PhaseStatus, TuiState};

/// A single progress message the pipeline reports to the TUI.
///
/// `Clone` + `Send` so it can cross the mpsc boundary from any pipeline task.
#[derive(Clone, Debug)]
pub enum TuiEvent {
    /// A phase transitioned: `Phase::Stun` is now `PhaseStatus::Active`, etc.
    Phase(Phase, PhaseStatus),
    /// A line for the event log (level affects color).
    Log(LogLevel, String),
    /// The own public address was discovered.
    OwnAddr(String),
    /// The peer public address was resolved.
    PeerAddr(String),
    /// The negotiated role (server/client) is known.
    Role(String),
    /// The certificate fingerprint, for out-of-band comparison.
    Fingerprint(String),
    /// The local listen port (client role) the user should connect to.
    LocalPort(u16),
    /// The remote target being forwarded to (server role).
    Target(String),
    /// The tunnel is up and forwarding.
    Ready,
    /// The tunnel closed (normal exit).
    Done(String),
    /// A fatal error occurred.
    Error(String),
}

/// Severity of a log line, mapping to a color in the UI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

/// A thread-safe handle the pipeline holds to report progress.
///
/// Wraps the mpsc sender; cloning is cheap and the sender can be dropped when
/// the TUI is off (a `None` handle emits nothing).
#[derive(Clone)]
pub struct TuiHandle {
    tx: Option<mpsc::Sender<TuiEvent>>,
}

impl TuiHandle {
    /// A no-op handle used when the TUI is disabled.
    pub fn disabled() -> Self {
        Self { tx: None }
    }

    pub fn emit(&self, ev: TuiEvent) {
        if let Some(tx) = &self.tx {
            // The receiver always owns the channel for the process lifetime,
            // so a closed sender is only a problem if the render loop exited
            // early (user pressed `q`); ignore that.
            let _ = tx.send(ev);
        }
    }

    /// True when the TUI is not running (events are silently dropped).
    pub fn is_disabled(&self) -> bool {
        self.tx.is_none()
    }
}

/// Construct a channel pair: the pipeline keeps `TuiHandle`, the render loop
/// receives from the `Receiver`.
pub fn channel() -> (TuiHandle, mpsc::Receiver<TuiEvent>) {
    let (tx, rx) = mpsc::channel();
    (TuiHandle { tx: Some(tx) }, rx)
}

// ── State application ────────────────────────────────────────────────────

/// Fold one event into the shared state (pure — no terminal I/O).
///
/// Splitting this out from the render loop makes it unit-testable.
pub fn apply_event(state: &mut TuiState, ev: TuiEvent) {
    match ev {
        TuiEvent::Phase(phase, status) => state.set_phase(phase, status),
        TuiEvent::Log(level, msg) => state.push_log(level, msg),
        TuiEvent::OwnAddr(a) => {
            state.push_log(LogLevel::Info, format!("own public address: {a}"));
            state.own_addr = Some(a);
        }
        TuiEvent::PeerAddr(a) => {
            state.push_log(LogLevel::Info, format!("peer address: {a}"));
            state.peer_addr = Some(a);
        }
        TuiEvent::Role(r) => {
            state.push_log(LogLevel::Info, format!("role: {r}"));
            state.role = Some(r);
        }
        TuiEvent::Fingerprint(f) => {
            state.push_log(LogLevel::Info, format!("cert fingerprint: {f}"));
            state.fingerprint = Some(f);
        }
        TuiEvent::LocalPort(p) => {
            state.push_log(LogLevel::Info, format!("local port: {p}"));
            state.local_port = Some(p);
        }
        TuiEvent::Target(t) => {
            state.push_log(LogLevel::Info, format!("forwarding to: {t}"));
            state.target = Some(t);
        }
        TuiEvent::Ready => {
            state.ready = true;
            state.push_log(LogLevel::Info, "tunnel is up — traffic is flowing".into());
        }
        TuiEvent::Done(msg) => {
            state.done = true;
            state.error = false;
            state.push_log(LogLevel::Info, msg);
        }
        TuiEvent::Error(msg) => {
            state.done = true;
            state.error = true;
            state.push_log(LogLevel::Error, msg);
        }
    }
}

/// The render loop. Owns the terminal until the pipeline signals `Done`/`Error`
/// or the user presses `q`/`Esc`.
pub fn run_render_loop(rx: mpsc::Receiver<TuiEvent>) -> std::io::Result<()> {
    // Terminal setup.
    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    loop {
        // Drain any pending events before drawing, and bump the spinner tick.
        let mut quit = false;
        {
            let mut state = STATE_GUARD.lock().unwrap_or_else(|p| p.into_inner());
            state.tick = state.tick.wrapping_add(1);
            while let Ok(ev) = rx.try_recv() {
                apply_event(&mut state, ev);
            }
        }

        // Draw, then poll the terminal with a short timeout so we stay
        // responsive to keyboard input without busy-spinning.
        terminal.draw(draw)?;

        if crossterm::event::poll(std::time::Duration::from_millis(60))? {
            match event::read()? {
                Event::Key(key) if key.kind == KeyEventKind::Press => {
                    if matches!(key.code, KeyCode::Char('q') | KeyCode::Esc) {
                        quit = true;
                    }
                }
                _ => {}
            }
        }

        if quit || terminal_state_done() {
            break;
        }
    }

    // Restore the terminal even on the error path.
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    Ok(())
}

// A process-lifetime state holder so the render loop and a (future) keyboard
// handler can share it. In this MVP the render loop is the only consumer, but
// keeping it behind a Mutex makes the design honest about ownership.
static STATE_GUARD: std::sync::LazyLock<std::sync::Mutex<TuiState>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(TuiState::default()));

fn terminal_state_done() -> bool {
    let s = STATE_GUARD.lock().unwrap_or_else(|p| p.into_inner());
    s.done
}

// ── Drawing ──────────────────────────────────────────────────────────────

fn draw(f: &mut Frame) {
    let state = STATE_GUARD
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone();
    let area = f.area();

    // Three vertical regions: header, body (diagram + log), footer.
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // header
            Constraint::Min(8),    // body
            Constraint::Length(1), // footer
        ])
        .split(area);

    draw_header(f, chunks[0], &state);
    draw_body(f, chunks[1], &state);
    draw_footer(f, chunks[2], &state);
}

fn draw_header(f: &mut Frame, area: Rect, state: &TuiState) {
    let title = match (state.done, state.error) {
        (true, true) => Line::from(Span::styled(
            " p2p-tunnel  —  ERROR ",
            Style::default().red().bold(),
        )),
        (true, false) => Line::from(Span::styled(
            " p2p-tunnel  —  CLOSED ",
            Style::default().green().bold(),
        )),
        _ if state.ready => Line::from(Span::styled(
            " p2p-tunnel  —  CONNECTED ",
            Style::default().cyan().bold(),
        )),
        _ => Line::from(Span::styled(" p2p-tunnel ", Style::default().cyan().bold())),
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border_style(state))
        .title(title);
    f.render_widget(block, area);
}

fn draw_body(f: &mut Frame, area: Rect, state: &TuiState) {
    let cols = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(6), // phase stepper
            Constraint::Length(7), // connection diagram
            Constraint::Min(3),    // event log
        ])
        .split(area);

    draw_phase_stepper(f, cols[0], state);
    draw_diagram(f, cols[1], state);
    draw_log(f, cols[2], state);
}

fn draw_phase_stepper(f: &mut Frame, area: Rect, state: &TuiState) {
    let phases = [
        (Phase::Stun, "STUN"),
        (Phase::Exchange, "EXCHANGE"),
        (Phase::Punch, "PUNCH"),
        (Phase::Role, "ROLE"),
        (Phase::Quic, "QUIC"),
        (Phase::Tunnel, "TUNNEL"),
    ];
    let mut spans = Vec::new();
    for (i, (phase, label)) in phases.iter().enumerate() {
        let status = state.status(*phase);
        let (icon, style) = match status {
            PhaseStatus::Done => ("✓", Style::default().green()),
            PhaseStatus::Active => {
                let c = spinner_char(state.tick);
                (c, Style::default().yellow().bold())
            }
            PhaseStatus::Pending => ("·", Style::default().dim()),
            PhaseStatus::Error => ("✗", Style::default().red()),
        };
        if i > 0 {
            spans.push(Span::styled(" ── ", Style::default().dark_gray()));
        }
        spans.push(Span::styled(format!("{icon} {label}"), style));
    }
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border_style(state))
        .title(" lifecycle ");
    f.render_widget(Paragraph::new(Line::from(spans)).block(block), area);
}

fn draw_diagram(f: &mut Frame, area: Rect, state: &TuiState) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border_style(state))
        .title(" connection ");
    let lines = vec![
        Line::from(vec![
            Span::styled(" you  ", Style::default().cyan().bold()),
            Span::raw(
                state
                    .own_addr
                    .clone()
                    .unwrap_or_else(|| "discovering…".into()),
            ),
        ]),
        Line::from(vec![
            Span::styled(" peer ", Style::default().magenta().bold()),
            Span::raw(state.peer_addr.clone().unwrap_or_else(|| "—".into())),
        ]),
        Line::from(vec![
            Span::styled(" role ", Style::default().dim()),
            Span::styled(
                state.role.clone().unwrap_or_else(|| "—".into()),
                Style::default().bold(),
            ),
        ]),
        Line::from(vec![
            Span::styled(" cert ", Style::default().dim()),
            Span::raw(shorten(
                &state.fingerprint.clone().unwrap_or_default(),
                area.width as usize,
            )),
        ]),
    ];
    f.render_widget(Paragraph::new(lines).block(block), area);
}

fn draw_log(f: &mut Frame, area: Rect, state: &TuiState) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border_style(state))
        .title(" events ");

    let items: Vec<ListItem> = state
        .logs
        .iter()
        .map(|(level, msg)| {
            let style = match level {
                LogLevel::Error => Style::default().red(),
                LogLevel::Warn => Style::default().yellow(),
                LogLevel::Debug => Style::default().dim(),
                LogLevel::Info => Style::default(),
            };
            ListItem::new(Line::from(Span::styled(msg.clone(), style)))
        })
        .collect();

    let list = List::new(items).block(block);
    let mut state_box = ListState::default();
    // Selecting the last item scrolls the list so the newest line is visible.
    state_box.select(if state.logs.is_empty() {
        None
    } else {
        Some(state.logs.len() - 1)
    });
    f.render_stateful_widget(list, area, &mut state_box);
}

fn draw_footer(f: &mut Frame, area: Rect, state: &TuiState) {
    let left = if state.done {
        String::from(" session ended ")
    } else if state.ready {
        String::from(" CONNECTED — traffic flowing ")
    } else {
        format!(" working on: {} ", phase_label(state.active_phase()))
    };
    let right = if state.done {
        String::from(" q to close ")
    } else if state.ready {
        String::from(" q to tear down ")
    } else {
        String::from(" q to abort ")
    };
    let line = Line::from(vec![
        Span::styled(left, Style::default().dark_gray().italic()),
        Span::raw("   "),
        Span::styled(right, Style::default().dark_gray().italic()),
    ]);
    f.render_widget(Paragraph::new(line), area);
}

fn border_style(state: &TuiState) -> Style {
    match (state.done, state.error) {
        (_, true) => Style::default().red(),
        (true, _) => Style::default().green(),
        _ if state.ready => Style::default().cyan(),
        _ => Style::default().dark_gray(),
    }
}

fn phase_label(phase: Phase) -> &'static str {
    match phase {
        Phase::Stun => "STUN discovery",
        Phase::Exchange => "address exchange",
        Phase::Punch => "hole punching",
        Phase::Role => "role negotiation",
        Phase::Quic => "QUIC handshake",
        Phase::Tunnel => "tunneling",
    }
}

/// Advance a 4-frame braille spinner based on a tick counter.
fn spinner_char(tick: u32) -> &'static str {
    match tick % 4 {
        0 => "⠋",
        1 => "⠙",
        2 => "⠹",
        3 => "⠸",
        _ => "⠋",
    }
}

/// Truncate a string to `max` chars (used for the fingerprint in narrow panes).
fn shorten(s: &str, max: usize) -> String {
    let s = s.trim();
    if s.is_empty() {
        return "—".into();
    }
    if s.len() <= max {
        return s.to_string();
    }
    // Show a head…tail slice so both ends are visible.
    let keep = max.saturating_sub(1).max(8);
    let head = s.get(..(keep / 2).max(4)).unwrap_or(s);
    let tail = s
        .get(s.len().saturating_sub(keep / 2).max(4)..)
        .unwrap_or("");
    format!("{head}…{tail}")
}
