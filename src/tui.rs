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
//!
//! **Interactive prompt (the address-exchange fallback).** The TUI owns the
//! terminal in raw mode, so a plain `read_line` from the pipeline would eat
//! raw bytes and the prompt would never appear. Instead the pipeline emits
//! [`TuiEvent::Prompt`]; the render loop switches to an inline line editor
//! (the UI keeps rendering, the user's input is visible at the bottom) and
//! replies with a [`PromptOutcome`]: the submitted line, a mode toggle (the
//! `t` key switches manual ⇄ Telegram), or an abort (`q`/Esc/Ctrl-C).
//!
//! **Keyboard.** Outside a prompt: `q`/Esc/Ctrl-C aborts the whole run (a
//! shared flag tells the pipeline to stop), and `t` switches the
//! address-exchange mode when a Telegram channel is configured.

use std::io::Write;
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

use crate::tui_state::{ExchangeMode, Phase, PhaseStatus, TuiState};

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
    /// The pipeline needs a line of text from the user. The render loop
    /// switches to the inline prompt editor and replies with the outcome on
    /// `reply_tx` (a submitted line, a mode toggle, or an abort).
    Prompt {
        prompt: String,
        reply_tx: mpsc::Sender<PromptOutcome>,
    },
    /// A working Telegram channel exists (or not) — the render loop shows or
    /// hides the `[t]` mode-toggle hint accordingly.
    TelegramChannel(bool),
}

/// The outcome of an interactive prompt, sent back to the pipeline.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PromptOutcome {
    /// The user submitted a line (may be empty; the caller validates).
    Line(String),
    /// The user pressed `t` to switch the address-exchange mode.
    ModeToggled,
    /// The user aborted the prompt (`q` / Esc / Ctrl-C).
    Aborted,
    /// stdin was closed (EOF; the non-TUI path only).
    Eof,
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
/// Wraps the mpsc sender plus two flags shared with the render loop:
/// the current exchange mode (flipped by the `t` key) and an abort flag
/// (set when the user quits outside a prompt). Cloning is cheap and the
/// sender can be dropped when the TUI is off (a `None` handle emits nothing).
#[derive(Clone)]
pub struct TuiHandle {
    tx: Option<mpsc::Sender<TuiEvent>>,
    mode: std::sync::Arc<std::sync::atomic::AtomicU8>,
    aborted: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl TuiHandle {
    /// A no-op handle used when the TUI is disabled. Stays in manual mode and
    /// is never aborted (there is no render loop to do either).
    pub fn disabled() -> Self {
        Self {
            tx: None,
            mode: std::sync::Arc::new(std::sync::atomic::AtomicU8::new(ExchangeMode::MANUAL_BITS)),
            aborted: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    pub fn new(tx: mpsc::Sender<TuiEvent>) -> Self {
        Self {
            tx: Some(tx),
            mode: std::sync::Arc::new(std::sync::atomic::AtomicU8::new(ExchangeMode::MANUAL_BITS)),
            aborted: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
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

    /// The shared render-loop side of this handle's flags.
    pub fn render_side(
        &self,
    ) -> (
        std::sync::Arc<std::sync::atomic::AtomicU8>,
        std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) {
        (self.mode.clone(), self.aborted.clone())
    }

    /// The current address-exchange mode (manual or Telegram).
    pub fn exchange_mode(&self) -> ExchangeMode {
        ExchangeMode::from_bits(self.mode.load(std::sync::atomic::Ordering::Relaxed))
    }

    /// Set the exchange mode (also used when the user presses `t`).
    pub fn set_exchange_mode(&self, mode: ExchangeMode) {
        self.mode
            .store(mode.to_bits(), std::sync::atomic::Ordering::Relaxed);
    }

    /// Whether the user has asked to abort (pressed `q`/Esc/Ctrl-C outside a
    /// prompt). The pipeline checks this between phases and at the end of
    /// every Telegram polling iteration so the run actually stops.
    pub fn aborted(&self) -> bool {
        self.aborted.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Ask the user for a line of text and return the outcome.
    ///
    /// TUI active: hands the request to the render loop, which switches to
    /// the inline prompt editor and replies on the mpsc. Pipeline blocked
    /// meanwhile is fine — the pipeline is otherwise idle waiting for this
    /// input.
    ///
    /// TUI disabled: a plain blocking `read_line` on stdin, exactly as before.
    ///
    /// Returns [`PromptOutcome::Eof`] on EOF (stdin closed / Ctrl-D) and
    /// `Err` on I/O errors.
    pub fn ask_line(&self, prompt: &str) -> std::io::Result<PromptOutcome> {
        if let Some(tx) = &self.tx {
            let (reply_tx, reply_rx) = mpsc::channel();
            tx.send(TuiEvent::Prompt {
                prompt: prompt.to_string(),
                reply_tx,
            })
            .map_err(|_| std::io::Error::other("TUI render loop has exited"))?;
            match reply_rx.recv() {
                Ok(outcome) => Ok(outcome),
                Err(_) => Ok(PromptOutcome::Aborted),
            }
        } else {
            print!("{prompt}");
            std::io::stdout().flush()?;
            let mut line = String::new();
            let n = std::io::stdin().read_line(&mut line)?;
            if n == 0 {
                return Ok(PromptOutcome::Eof);
            }
            Ok(PromptOutcome::Line(line))
        }
    }
}

/// Construct the channel pair: the pipeline keeps `TuiHandle`, the render
/// loop receives from the `Receiver` plus the shared mode/abort flags.
pub fn channel() -> (
    TuiHandle,
    mpsc::Receiver<TuiEvent>,
    std::sync::Arc<std::sync::atomic::AtomicU8>,
    std::sync::Arc<std::sync::atomic::AtomicBool>,
) {
    let (tx, rx) = mpsc::channel();
    let handle = TuiHandle::new(tx);
    let (mode, aborted) = handle.render_side();
    (handle, rx, mode, aborted)
}

// ── State application ────────────────────────────────────────────────────

/// Fold one event into the shared state (pure — no terminal I/O).
///
/// `TuiEvent::Prompt` is transport-only and carries no renderable state; it
/// is ignored here.
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
        TuiEvent::TelegramChannel(available) => {
            state.telegram_available = available;
            if available {
                state.push_log(
                    LogLevel::Info,
                    "telegram channel ready — press [t] to switch address-exchange mode".into(),
                );
            }
        }
        TuiEvent::Prompt { .. } => {}
    }
}

/// The render loop. Owns the terminal until the pipeline signals `Done`/`Error`
/// or the user quits (`q`/Esc/Ctrl-C, which also sets `aborted` so the
/// pipeline stops).
///
/// `mode` is the shared exchange-mode flag (flipped by the `t` key); `aborted`
/// is set when the user quits outside a prompt.
pub fn run_render_loop(
    rx: mpsc::Receiver<TuiEvent>,
    mode: std::sync::Arc<std::sync::atomic::AtomicU8>,
    aborted: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> std::io::Result<()> {
    // Terminal setup.
    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut quit = false;
    loop {
        // Drain any pending events before drawing. A `Prompt` request is
        // handled inline (it blocks until the user submits/aborts); everything
        // else is folded into state.
        let mut state = STATE_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        state.tick = state.tick.wrapping_add(1);
        state.exchange_mode =
            ExchangeMode::from_bits(mode.load(std::sync::atomic::Ordering::Relaxed));
        while let Ok(ev) = rx.try_recv() {
            match ev {
                TuiEvent::Prompt { prompt, reply_tx } => {
                    drop(state); // release the lock while we touch the terminal
                    let available = terminal_state_telegram();
                    let outcome = prompt_editor(&mut terminal, &prompt, &mode, available);
                    let _ = reply_tx.send(outcome);
                    state = STATE_GUARD.lock().unwrap_or_else(|p| p.into_inner());
                }
                other => apply_event(&mut state, other),
            }
        }
        drop(state);

        // Draw, then poll the terminal with a short timeout so we stay
        // responsive to keyboard input without busy-spinning.
        terminal.draw(draw)?;

        let key_event = match crossterm::event::poll(std::time::Duration::from_millis(60))? {
            true => event::read()?,
            false => continue,
        };
        if let Event::Key(key) = key_event {
            if key.kind != KeyEventKind::Press {
                continue;
            }
            let quit_key = matches!(
                key.code,
                KeyCode::Char('q') | KeyCode::Char('Q') | KeyCode::Esc
            ) || ctrl_c(&key);
            if quit_key {
                // q / Esc / Ctrl-C: abort the run, not just the UI.
                if !terminal_state_done() {
                    aborted.store(true, std::sync::atomic::Ordering::Relaxed);
                }
                quit = true;
            } else if matches!(key.code, KeyCode::Char('t') | KeyCode::Char('T'))
                && terminal_state_telegram()
                && !terminal_state_done()
            {
                let cur = ExchangeMode::from_bits(mode.load(std::sync::atomic::Ordering::Relaxed));
                let next = if cur == ExchangeMode::Telegram {
                    ExchangeMode::Manual
                } else {
                    ExchangeMode::Telegram
                };
                mode.store(next.to_bits(), std::sync::atomic::Ordering::Relaxed);
                let mut s = STATE_GUARD.lock().unwrap_or_else(|p| p.into_inner());
                s.exchange_mode = next;
                s.push_log(
                    LogLevel::Info,
                    format!("address exchange mode: {}", next.as_str()),
                );
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

/// Inline line editor used while a prompt is active. The UI keeps rendering
/// (the input is drawn at the bottom), so the user always sees what they are
/// typing. Keys: printable/space append, Backspace deletes, Enter submits,
/// `t` toggles the exchange mode (when Telegram is available), `q`/Esc/Ctrl-C
/// abort.
fn prompt_editor(
    terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    prompt: &str,
    mode: &std::sync::Arc<std::sync::atomic::AtomicU8>,
    telegram_available: bool,
) -> PromptOutcome {
    let mut input = String::new();
    let outcome = loop {
        // Show the prompt + current input while we wait for the next key.
        {
            let mut s = STATE_GUARD.lock().unwrap_or_else(|p| p.into_inner());
            s.prompt = Some((prompt.to_string(), input.clone()));
        }
        if terminal.draw(draw).is_err() {
            break PromptOutcome::Aborted;
        }
        let key_event = match event::read() {
            Ok(e) => e,
            Err(_) => break PromptOutcome::Aborted,
        };
        let Event::Key(key) = key_event else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }
        match key.code {
            KeyCode::Enter => break PromptOutcome::Line(std::mem::take(&mut input)),
            KeyCode::Backspace => {
                input.pop();
            }
            KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('Q') => {
                break PromptOutcome::Aborted;
            }
            KeyCode::Char('c') if ctrl_c(&key) => break PromptOutcome::Aborted,
            KeyCode::Char('t') | KeyCode::Char('T') if telegram_available => {
                let cur = ExchangeMode::from_bits(mode.load(std::sync::atomic::Ordering::Relaxed));
                let next = if cur == ExchangeMode::Telegram {
                    ExchangeMode::Manual
                } else {
                    ExchangeMode::Telegram
                };
                mode.store(next.to_bits(), std::sync::atomic::Ordering::Relaxed);
                break PromptOutcome::ModeToggled;
            }
            KeyCode::Char(c) if c.is_ascii_graphic() || c == ' ' => {
                input.push(c);
            }
            _ => {}
        }
    };
    // Clear the prompt line and reflect any mode change before the regular
    // render resumes.
    let mut s = STATE_GUARD.lock().unwrap_or_else(|p| p.into_inner());
    s.prompt = None;
    s.exchange_mode = ExchangeMode::from_bits(mode.load(std::sync::atomic::Ordering::Relaxed));
    outcome
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

fn terminal_state_telegram() -> bool {
    let s = STATE_GUARD.lock().unwrap_or_else(|p| p.into_inner());
    s.telegram_available
}

/// True for a Ctrl-C key event (in raw mode the terminal does not translate
/// it to SIGINT; we handle it ourselves).
fn ctrl_c(key: &crossterm::event::KeyEvent) -> bool {
    key.code == crossterm::event::KeyCode::Char('c')
        && key
            .modifiers
            .contains(crossterm::event::KeyModifiers::CONTROL)
}

// ── Drawing ──────────────────────────────────────────────────────────────

fn draw(f: &mut Frame) {
    let state = STATE_GUARD
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone();
    let area = f.area();
    let prompt_active = state.prompt.is_some();

    // Four vertical regions: header, body (diagram + log), footer (the footer
    // grows by one line while a prompt is active, to host the input line).
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),                                 // header
            Constraint::Min(8),                                    // body
            Constraint::Min(1),                                    // footer hints
            Constraint::Length(if prompt_active { 1 } else { 0 }), // input line
        ])
        .split(area);

    draw_header(f, chunks[0], &state);
    draw_body(f, chunks[1], &state);
    draw_footer(f, chunks[2], &state);
    if prompt_active {
        draw_prompt_line(f, chunks[3], &state);
    }
}

/// The prompt + live input line, drawn at the very bottom while a prompt is
/// active. The area is one line tall; the input follows the prompt text with
/// a blinking cursor. (ratatui clips overlong content at character
/// boundaries, so no manual truncation is needed.)
fn draw_prompt_line(f: &mut Frame, area: Rect, state: &TuiState) {
    let (prompt, input) = state.prompt.as_ref().expect("checked by draw");
    let cursor = if state.tick.is_multiple_of(2) {
        "▏"
    } else {
        " "
    };
    let line = Line::from(vec![
        Span::styled(" › ", Style::default().cyan().bold()),
        Span::styled(prompt.clone(), Style::default().bold()),
        Span::raw(input.clone()),
        Span::styled(cursor.to_string(), Style::default().cyan()),
    ]);
    f.render_widget(Paragraph::new(line), area);
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
    } else if state.telegram_available {
        format!(
            " [{}: {}]",
            phase_label(state.active_phase()),
            state.exchange_mode.as_str()
        )
    } else {
        format!(" working on: {} ", phase_label(state.active_phase()))
    };
    let right = if state.done {
        String::from(" q to close ")
    } else if state.ready {
        String::from(" q to tear down ")
    } else {
        // Offer the mode toggle only while a working Telegram channel exists
        // and the address exchange is not over.
        if state.telegram_available && state.peer_addr.is_none() {
            String::from(" [t] toggle mode · q to abort ")
        } else {
            String::from(" q to abort ")
        }
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
